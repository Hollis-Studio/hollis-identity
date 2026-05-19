# Hollis Identity Infrastructure

Terraform stack for the standalone Identity Service in AWS account `344345273019`
by default.

It provisions:

- ECR repository
- VPC with public ALB subnets and private ECS/RDS subnets
- ECS Fargate cluster, task definition, and service
- RDS PostgreSQL with encrypted storage
- Secrets Manager entries for database and JWT/application secrets
- RS256 JWT key pair for production token signing
- CloudWatch logs
- AWS WAF rate-based rule attached to the ALB

## Account Strategy

This stack is account-aware through `allowed_account_ids` and `aws_account_id`.
The suite currently uses the same Hollis AWS account for Health, Identity, and
future services, with separation by Terraform state, environment, service name,
network/security group boundaries, IAM roles, and Secrets Manager namespaces.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
```

Do not apply production without first setting:

- `environment = "prod"`
- `db_multi_az = true`
- `certificate_arn` to an ACM certificate in the same region
- a production `identity_domain_name`
- a production `reset_password_url` that points at the frontend reset-password page, not the Identity API
- a production-specific Terraform backend/state location

The application container must be pushed to the output `ecr_repository_url` with
the configured `image_tag` before ECS tasks can become healthy.
