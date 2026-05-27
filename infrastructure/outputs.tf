output "aws_account_id" {
  description = "AWS account ID of the caller identity."
  value       = data.aws_caller_identity.current.account_id
}

output "ecr_repository_url" {
  description = "ECR URL to push the Identity container image to."
  value       = aws_ecr_repository.identity.repository_url
}

output "target_group_arn" {
  description = "ARN of the new Identity ALB target group."
  value       = aws_lb_target_group.identity.arn
}

output "alb_listener_rule_arn" {
  description = "ARN of the new Identity ALB listener rule (additive — does not modify Health's rules)."
  value       = aws_lb_listener_rule.identity_host.arn
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.identity.name
}

output "database_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials and DATABASE_URL."
  value       = aws_secretsmanager_secret.database.arn
  sensitive   = true
}

output "app_secret_arn" {
  description = "ARN of the Secrets Manager secret containing JWT keys, ENCRYPTION_KEY, and PASSWORD_PEPPER."
  value       = aws_secretsmanager_secret.app.arn
  sensitive   = true
}
