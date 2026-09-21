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
#
# PASSWORD_PEPPER is the dangerous one: every User.passwordHash was computed
# over password + pepper, so regenerating it makes every password on the
# platform permanently unverifiable. See docs/SECRETS-ESCROW.md.
#
# WHAT THE lifecycle BLOCKS BELOW ACTUALLY BUY — and what they do not.
#
# Both `prevent_destroy` and `ignore_changes` are evaluated by comparing the
# configuration against a PRIOR STATE ENTRY. They close the accidents that
# happen while the resource is in state:
#
#   * `terraform destroy` of the stack                     -> plan-time error
#   * `terraform taint` / `-replace=random_password.*`     -> plan-time error
#   * deleting a resource block to "clean up" the unused
#     RS256 material and catching the pepper in the blast
#     radius                                               -> plan-time error
#   * a regenerated random value rewriting the live app
#     secret in place (PutSecretValue)                     -> ignored (app only)
#
# They do NOT close the fresh-state case — an apply from an uninitialised
# working copy, or after the state object is lost. With no prior state every
# resource is a CREATE, and lifecycle meta-arguments have nothing to compare
# against: `random_password` generates new values and
# `aws_secretsmanager_secret_version.app` is created, not updated, so
# `ignore_changes` never runs. In practice such a run aborts first, because
# CreateSecret on an existing name returns ResourceExistsException — but that
# is an AWS name collision, not a guard, and it disappears the moment someone
# `terraform import`s the secret to get past the error, at which point the
# version is still a create.
#
# The only terraform-level fix for the fresh-state class is to stop generating
# these values here at all: create them once out of band and read the ARN with
# `data "aws_secretsmanager_secret"`, so they have no representation in state.
# That is a state-surgery migration and needs Isaac's authorisation — it is
# Part 3's "longer term" item in docs/SECRETS-ESCROW.md, still open.
#
# Operational consequence of what IS applied here: a deliberate teardown is now
# a two-step (remove the lifecycle block, then destroy), and a deliberate
# rotation of the app bundle is an `aws secretsmanager put-secret-value` call
# rather than an `apply`. Both are the right way round for values whose loss is
# unrecoverable.
# ---------------------------------------------------------------------------

resource "random_password" "db" {
  length  = 32
  special = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "random_password" "jwt_secret" {
  length  = 48
  special = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "random_password" "encryption_key" {
  length  = 48
  special = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "random_password" "password_pepper" {
  length  = 48
  special = true

  lifecycle {
    prevent_destroy = true
  }
}

# RS256 key material — retained as unused fallback so state doesn't drift if
# JWT_ALGORITHM is changed back to RS256 in the future.
resource "tls_private_key" "jwt" {
  algorithm = "RSA"
  rsa_bits  = 2048

  # Same reasoning: a replace here rewrites JWT_PRIVATE_KEY/JWT_PUBLIC_KEY in
  # the same secret version as the pepper.
  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Secrets Manager — app bundle (JWT keys, encryption, pepper)
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "app" {
  name        = "${local.name}/app"
  description = "JWT keys, ENCRYPTION_KEY, and PASSWORD_PEPPER for ${local.name}."

  lifecycle {
    prevent_destroy = true
  }
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

  # Secrets Manager — not Terraform — is now the system of record for these six
  # values. Terraform writes them exactly once, at create; after that any drift
  # in the rendered JSON is ignored, so a regenerated random_password can no
  # longer push a new pepper over the live secret.
  #
  # Safe to adopt today: the secret has exactly one version (AWSCURRENT,
  # created 2026-05-26 by this stack and never changed), so state and live
  # value agree and nothing legitimate is being suppressed.
  #
  # To rotate on purpose: `aws secretsmanager put-secret-value --secret-id
  # hollis-identity-prod/app` and force a new ECS deployment. Rotating the
  # pepper still invalidates every stored password hash — it is not a routine
  # operation.
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [secret_string]
  }
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

  lifecycle {
    prevent_destroy = true
  }
}

# Deliberately NOT `ignore_changes = [secret_string]`, unlike the app bundle.
# This value is derived from the shared RDS endpoint (`data.aws_db_instance
# .shared.address`/`.port`), and Terraform has to stay able to rewrite it when
# that endpoint moves. The irrecoverable part — the generated password itself —
# is already pinned by `prevent_destroy` on `random_password.db` above, and a
# lost DB password is recoverable (reset the Postgres role and re-put the
# secret), unlike the pepper.
#
# Note `secret_string` is ForceNew on this resource, so a change here is a
# destroy-and-recreate of the version, not an in-place update; that is why the
# version is left unguarded while the secret container above is not.
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
