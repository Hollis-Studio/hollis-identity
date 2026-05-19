resource "aws_iam_role" "task_execution" {
  name = "${local.name}-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name = "${local.name}-secrets"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]
      Resource = [
        aws_secretsmanager_secret.app.arn,
        aws_secretsmanager_secret.database.arn
      ]
    }]
  })
}

resource "aws_iam_role" "task" {
  name = "${local.name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "task_ses" {
  count = var.email_provider == "ses" ? 1 : 0
  name  = "${local.name}-ses"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_ecs_cluster" "identity" {
  name = local.name
}

resource "aws_lb" "identity" {
  name               = local.name
  load_balancer_type = "application"
  subnets            = aws_subnet.public[*].id
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "identity" {
  name        = local.name
  port        = 4001
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/health"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.identity.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.identity.arn
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.identity.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.identity.arn
  }
}

resource "aws_ecs_task_definition" "identity" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name      = var.project
    image     = "${aws_ecr_repository.identity.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{
      containerPort = 4001
      protocol      = "tcp"
    }]

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "PORT", value = "4001" },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "JWT_ALGORITHM", value = "RS256" },
      { name = "JWT_ISSUER", value = local.issuer },
      { name = "JWT_AUDIENCES", value = var.jwt_audiences },
      { name = "CORS_ORIGINS", value = var.cors_origins },
      { name = "EMAIL_PROVIDER", value = var.email_provider },
      { name = "EMAIL_FROM", value = var.email_from },
      { name = "RESET_PASSWORD_URL", value = var.reset_password_url },
      { name = "LOG_LEVEL", value = "info" }
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.database.arn}:DATABASE_URL::" },
      { name = "JWT_SECRET", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_SECRET::" },
      { name = "JWT_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_PRIVATE_KEY::" },
      { name = "JWT_PUBLIC_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_PUBLIC_KEY::" },
      { name = "JWT_KEY_ID", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_KEY_ID::" },
      { name = "ENCRYPTION_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:ENCRYPTION_KEY::" },
      { name = "PASSWORD_PEPPER", valueFrom = "${aws_secretsmanager_secret.app.arn}:PASSWORD_PEPPER::" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.identity.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "identity" {
  name            = local.name
  cluster         = aws_ecs_cluster.identity.id
  task_definition = aws_ecs_task_definition.identity.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.identity.arn
    container_name   = var.project
    container_port   = 4001
  }

  depends_on = [aws_lb_listener.http]
}
