output "aws_account_id" {
  description = "AWS account ID of the caller identity."
  value       = data.aws_caller_identity.current.account_id
}

output "ecr_repository_url" {
  description = "ECR URL to push the container image to."
  value       = aws_ecr_repository.identity.repository_url
}

output "alb_dns_name" {
  description = "ALB DNS name; use for a Route 53 alias or CNAME."
  value       = aws_lb.identity.dns_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.identity.name
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
