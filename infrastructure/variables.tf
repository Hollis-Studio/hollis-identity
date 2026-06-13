variable "aws_account_id" {
  description = "AWS account that this stack is allowed to target."
  type        = string
  default     = "344345273019"
}

variable "aws_region" {
  description = "AWS region for the Identity service."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "project" {
  description = "Project/service name used in resource names."
  type        = string
  default     = "hollis-identity"
}

variable "image_tag" {
  description = "Container image tag deployed by ECS."
  type        = string
  default     = "latest"
}

# ---------------------------------------------------------------------------
# Shared infrastructure references (NEVER managed by this stack)
# ---------------------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID that contains the shared ALB, ECS cluster, and RDS instance."
  type        = string
  default     = "vpc-0abe755c07479d64a"
}

variable "private_subnet_ids" {
  description = "Private subnet IDs in the shared VPC (currently unused: no NAT/VPC endpoints exist, so tasks run in public subnets instead)."
  type        = list(string)
  default     = ["subnet-0d5672f9161c08a46", "subnet-0d8d2cf589dcad61e"]
}

variable "public_subnet_ids" {
  description = "Public subnet IDs in the shared VPC for ECS task placement (egress via IGW with a public IP; matches hollis-prod-api)."
  type        = list(string)
  default     = ["subnet-0dcd09f364647e0a3", "subnet-04d00419be5cb0802"]
}

variable "alb_name" {
  description = "Name of the existing shared ALB to attach to."
  type        = string
  default     = "hollis-prod-alb"
}

variable "ecs_cluster_name" {
  description = "Name of the existing shared ECS cluster."
  type        = string
  default     = "hollis-prod-cluster"
}

variable "rds_identifier" {
  description = "Identifier of the existing shared RDS instance."
  type        = string
  default     = "hollis-prod-postgres"
}

variable "rds_security_group_id" {
  description = "Security group ID already attached to hollis-prod-postgres. An additive ingress rule is appended — the SG itself is never managed by this stack."
  type        = string
  default     = "sg-072f4e44c43356914"
}

# ---------------------------------------------------------------------------
# Identity-specific config
# ---------------------------------------------------------------------------

variable "identity_domain_name" {
  description = "Public host name for the Identity API and JWT issuer."
  type        = string
  default     = "identity.hollis.health"
}

variable "certificate_arn" {
  description = "ACM wildcard certificate ARN covering identity.hollis.health. Already attached to hollis-prod-alb; referenced here only for documentation."
  type        = string
  default     = "arn:aws:acm:us-east-1:344345273019:certificate/89bb25b7-f69d-4af5-a6f1-fe226161eb2a"
}

variable "reset_password_url" {
  description = "Frontend password reset page URL used in password reset emails."
  type        = string
  default     = "https://hollis.health/reset-password"
}

variable "verify_email_url" {
  description = "Suite email verification page URL used in email verification emails."
  type        = string
  default     = "https://www.hollis.health/verify?type=email"
}

variable "cors_origins" {
  description = "Comma-separated allowed browser origins."
  type        = string
  default     = "https://hollis.health,https://admin.hollis.health"
}

variable "jwt_audiences" {
  description = "Comma-separated JWT audiences. Must include hollis-workouts so Workouts can verify tokens."
  type        = string
  default     = "hollis-health,hollis-workouts"
}

variable "google_client_id" {
  description = "Google OAuth client ID used as the expected `aud` when verifying Google id_tokens. Public value (not a secret); the mobile clients present id_tokens minted for this audience."
  type        = string
  default     = "669071559387-51r0f2ksiediq3rmlqpegnsvddjpndte.apps.googleusercontent.com"
}

variable "apple_service_id" {
  description = "Expected `aud` claim when verifying Apple id_tokens. For native iOS Sign in with Apple this is the app's bundle identifier. Public value (not a secret). Apple sign-in fails closed without it (PROVIDER_NOT_CONFIGURED → 503)."
  type        = string
  default     = "com.hollishealth.workouts"
}

variable "email_from" {
  description = "Verified SES sender address."
  type        = string
  default     = "noreply@hollis.health"
}

variable "email_provider" {
  description = "Identity email provider."
  type        = string
  default     = "ses"

  validation {
    condition     = contains(["console", "ses"], var.email_provider)
    error_message = "email_provider must be console or ses."
  }
}

variable "desired_count" {
  description = "Number of ECS tasks."
  type        = number
  default     = 2
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory MiB."
  type        = number
  default     = 1024
}

variable "log_level" {
  description = "LOG_LEVEL injected into the container (debug|info|warn|error)."
  type        = string
  default     = "info"
}
