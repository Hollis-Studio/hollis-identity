locals {
  name    = "${var.project}-${var.environment}"
  issuer  = "https://${var.identity_domain_name}"
  db_name = "hollis_identity"

  tags = {
    ManagedBy   = "terraform"
    Project     = var.project
    Environment = var.environment
    Suite       = "hollis"
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# ECR repository (new — identity-specific)
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "identity" {
  name                 = local.name
  image_tag_mutability = "MUTABLE"
  force_delete         = var.environment != "prod"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ---------------------------------------------------------------------------
# CloudWatch log group (new — identity-specific)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "identity" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.environment == "prod" ? 90 : 30
}

# ---------------------------------------------------------------------------
# Generated secrets (all random values managed in Terraform state)
# ---------------------------------------------------------------------------

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

# RS256 key material — retained as unused fallback so state doesn't drift if
# JWT_ALGORITHM is changed back to RS256 in the future.
resource "tls_private_key" "jwt" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# ---------------------------------------------------------------------------
# Secrets Manager — app bundle (JWT keys, encryption, pepper)
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "app" {
  name        = "${local.name}/app"
  description = "JWT keys, ENCRYPTION_KEY, and PASSWORD_PEPPER for ${local.name}."
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

# ---------------------------------------------------------------------------
# Secrets Manager — database connection string
#
# Points at the SHARED hollis-prod-postgres instance.
# The hollis_identity logical database must be created out-of-band:
#   psql "postgresql://<admin_user>:<pass>@<shared_rds_address>:5432/postgres"
#   CREATE DATABASE hollis_identity;
#   CREATE USER hollis_identity WITH PASSWORD '<random_password.db.result>';
#   GRANT ALL PRIVILEGES ON DATABASE hollis_identity TO hollis_identity;
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "database" {
  name        = "${local.name}/database"
  description = "DATABASE_URL for hollis_identity on the shared hollis-prod-postgres."
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username     = "hollis_identity"
    password     = random_password.db.result
    dbname       = local.db_name
    host         = data.aws_db_instance.shared.address
    port         = data.aws_db_instance.shared.port
    DATABASE_URL = "postgresql://hollis_identity:${random_password.db.result}@${data.aws_db_instance.shared.address}:${data.aws_db_instance.shared.port}/${local.db_name}?sslmode=require&connection_limit=20&pool_timeout=10"
  })
}
