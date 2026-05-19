resource "aws_db_subnet_group" "identity" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "identity" {
  identifier              = local.name
  engine                  = "postgres"
  engine_version          = "16"
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage
  max_allocated_storage   = max(var.db_allocated_storage, 100)
  db_name                 = local.db_name
  username                = local.db_username
  password                = random_password.db.result
  db_subnet_group_name    = aws_db_subnet_group.identity.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = var.db_multi_az
  deletion_protection     = var.environment == "prod"
  skip_final_snapshot     = var.environment != "prod"
  backup_retention_period = var.environment == "prod" ? 14 : 3
  apply_immediately       = var.environment != "prod"
}
