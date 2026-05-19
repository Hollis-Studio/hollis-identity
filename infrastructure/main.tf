locals {
  name        = "${var.project}-${var.environment}"
  issuer      = "https://${var.identity_domain_name}"
  az_count    = 2
  vpc_cidr    = "10.42.0.0/16"
  db_name     = "hollis_identity"
  db_username = "hollis_identity"

  tags = {
    ManagedBy   = "terraform"
    Project     = var.project
    Environment = var.environment
    Suite       = "hollis"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

resource "aws_ecr_repository" "identity" {
  name                 = local.name
  image_tag_mutability = "MUTABLE"
  force_delete         = var.environment != "prod"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "identity" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.environment == "prod" ? 90 : 30
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_password" "jwt_secret" {
  length  = 48
  special = true
}

resource "random_password" "encryption_key" {
  length  = 48
  special = true
}

resource "random_password" "password_pepper" {
  length  = 48
  special = true
}

resource "tls_private_key" "jwt" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_secretsmanager_secret" "app" {
  name_prefix = "${local.name}/app/"
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    JWT_SECRET      = random_password.jwt_secret.result
    JWT_PRIVATE_KEY = tls_private_key.jwt.private_key_pem
    JWT_PUBLIC_KEY  = tls_private_key.jwt.public_key_pem
    JWT_KEY_ID      = "${local.name}-primary"
    ENCRYPTION_KEY  = random_password.encryption_key.result
    PASSWORD_PEPPER = random_password.password_pepper.result
  })
}

resource "aws_secretsmanager_secret" "database" {
  name_prefix = "${local.name}/database/"
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username     = local.db_username
    password     = random_password.db.result
    dbname       = local.db_name
    host         = aws_db_instance.identity.address
    port         = aws_db_instance.identity.port
    DATABASE_URL = "postgresql://${local.db_username}:${random_password.db.result}@${aws_db_instance.identity.address}:${aws_db_instance.identity.port}/${local.db_name}?sslmode=require&connection_limit=20&pool_timeout=10"
  })
}
