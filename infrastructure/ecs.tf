# ---------------------------------------------------------------------------
# Data sources — existing shared infrastructure (NEVER managed by this stack)
# ---------------------------------------------------------------------------

data "aws_ecs_cluster" "shared" {
  cluster_name = var.ecs_cluster_name
}

data "aws_lb" "shared" {
  name = var.alb_name
}

# Reference the HTTPS listener (port 443) on the shared ALB.
# This stack creates only an aws_lb_listener_rule attached to this listener —
# it never creates, modifies, or destroys the listener itself.
data "aws_lb_listener" "https" {
  load_balancer_arn = data.aws_lb.shared.arn
  port              = 443
}

# ---------------------------------------------------------------------------
# IAM — dedicated execution and task roles (do NOT share with Health's roles)
# ---------------------------------------------------------------------------

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
        aws_secretsmanager_secret.database.arn,
        data.aws_secretsmanager_secret.database_ssl_ca.arn,
      ]
    }]
  })
}

data "aws_secretsmanager_secret" "database_ssl_ca" {
  name = "hollis-prod/identity/database-ssl-ca"
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

# ---------------------------------------------------------------------------
# ALB target group (new — identity-specific)
# ---------------------------------------------------------------------------

resource "aws_lb_target_group" "identity" {
  name        = local.name
  port        = 4001
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.shared.id

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

# ---------------------------------------------------------------------------
# ALB listener rule (new — ADDITIVE only)
#
# Attaches to the existing HTTPS listener via data source; only adds a
# host-based routing rule.  Terraform never owns the listener default_action
# and cannot modify or destroy Health's rules.
#
# Priority 150 — Health uses 100 (admin.hollis.health), Workouts uses 200.
# ---------------------------------------------------------------------------

resource "aws_lb_listener_rule" "identity_host" {
  listener_arn = data.aws_lb_listener.https.arn
  priority     = 150

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.identity.arn
  }

  condition {
    host_header {
      values = [var.identity_domain_name]
    }
  }
}

# ---------------------------------------------------------------------------
# ECS task definition
# ---------------------------------------------------------------------------

resource "aws_ecs_task_definition" "identity" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
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
      # HS256 remains supported. Workouts currently verifies via remote /verify.
      # JWT_PRIVATE_KEY / JWT_PUBLIC_KEY remain in the app secret bundle as an
      # unused fallback in case RS256 is re-enabled in the future.
      { name = "JWT_ALGORITHM", value = "HS256" },
      { name = "JWT_ISSUER", value = local.issuer },
      # JWT_AUDIENCES must include "hollis-workouts" so Workouts can verify tokens.
      { name = "JWT_AUDIENCES", value = var.jwt_audiences },
      # Expected `aud` for Google id_token verification. Public OAuth client ID,
      # not a secret. Required — Google sign-in fails closed without it.
      { name = "GOOGLE_CLIENT_ID", value = var.google_client_id },
      { name = "CORS_ORIGINS", value = var.cors_origins },
      { name = "EMAIL_PROVIDER", value = var.email_provider },
      { name = "EMAIL_FROM", value = var.email_from },
      { name = "RESET_PASSWORD_URL", value = var.reset_password_url },
      { name = "VERIFY_EMAIL_URL", value = var.verify_email_url },
      { name = "LOG_LEVEL", value = var.log_level },
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.database.arn}:DATABASE_URL::" },
      { name = "DATABASE_SSL_CA", valueFrom = data.aws_secretsmanager_secret.database_ssl_ca.arn },
      { name = "JWT_SECRET", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_SECRET::" },
      { name = "JWT_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_PRIVATE_KEY::" },
      { name = "JWT_PUBLIC_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_PUBLIC_KEY::" },
      { name = "JWT_KEY_ID", valueFrom = "${aws_secretsmanager_secret.app.arn}:JWT_KEY_ID::" },
      { name = "ENCRYPTION_KEY", valueFrom = "${aws_secretsmanager_secret.app.arn}:ENCRYPTION_KEY::" },
      { name = "PASSWORD_PEPPER", valueFrom = "${aws_secretsmanager_secret.app.arn}:PASSWORD_PEPPER::" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.identity.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

# ---------------------------------------------------------------------------
# ECS service — joins the existing cluster; routes via the new TG + rule
# ---------------------------------------------------------------------------

resource "aws_ecs_service" "identity" {
  name            = local.name
  cluster         = data.aws_ecs_cluster.shared.arn
  task_definition = aws_ecs_task_definition.identity.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Tasks run in the PUBLIC subnets with a public IP (egress via the VPC IGW),
  # mirroring how hollis-prod-api runs. The private subnets have no NAT/VPC
  # endpoints, so tasks placed there cannot reach Secrets Manager / ECR. The
  # ECS SG only allows ingress from the shared ALB, so the public IP is egress-only.
  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.identity.arn
    container_name   = var.project
    container_port   = 4001
  }

  depends_on = [aws_lb_listener_rule.identity_host]
}
