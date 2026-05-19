output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "ecr_repository_url" {
  value = aws_ecr_repository.identity.repository_url
}

output "alb_dns_name" {
  value = aws_lb.identity.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.identity.name
}

output "ecs_service_name" {
  value = aws_ecs_service.identity.name
}

output "database_secret_arn" {
  value     = aws_secretsmanager_secret.database.arn
  sensitive = true
}

output "app_secret_arn" {
  value     = aws_secretsmanager_secret.app.arn
  sensitive = true
}
