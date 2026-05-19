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
  default     = "dev"
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

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener. Leave empty to create HTTP-only dev ALB."
  type        = string
  default     = ""
}

variable "identity_domain_name" {
  description = "Public host name for the Identity API and JWT issuer."
  type        = string
  default     = "identity.dev.hollis.health"
}

variable "reset_password_url" {
  description = "Frontend password reset page URL used in password reset emails. This is not the Identity API URL."
  type        = string
  default     = "https://hollis.health/reset-password"
}

variable "cors_origins" {
  description = "Comma-separated allowed browser origins."
  type        = string
  default     = "http://localhost:3000,http://localhost:3001"
}

variable "jwt_audiences" {
  description = "Comma-separated JWT audiences."
  type        = string
  default     = "hollis-health,hollis-workouts"
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

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Initial RDS storage in GiB."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Enable RDS Multi-AZ. Use true for staging/prod."
  type        = bool
  default     = false
}

variable "waf_rate_limit" {
  description = "ALB WAF per-IP request limit over a rolling five-minute window."
  type        = number
  default     = 1000
}
