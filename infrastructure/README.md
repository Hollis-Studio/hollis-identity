# Infrastructure

Placeholder for IaC definitions (Terraform / CDK) for the Hollis Identity Service ECS Fargate deployment.

TODO(W6-infra): Add Terraform modules or CDK stacks for:
- ECS Fargate service + task definition
- RDS PostgreSQL instance (or shared cluster)
- ALB target group / listener rules
- IAM roles and security groups
- Secrets Manager entries for JWT_SECRET, BCRYPT_PEPPER, DATABASE_URL
