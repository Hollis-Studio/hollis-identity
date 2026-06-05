# Hollis Identity Infrastructure

Terraform stack for the standalone Identity Service in AWS account `344345273019`
by default.

It provisions:

- ECR repository (image scanning enabled, `MUTABLE` tags)
- VPC (`10.42.0.0/16`) with 2 public subnets (ALB), 2 private subnets (ECS/RDS), per-AZ NAT Gateways with Elastic IPs, and matching route tables
- Application Load Balancer in the public subnets; HTTP listener always created, HTTPS listener (TLS 1.3, policy `ELBSecurityPolicy-TLS13-1-2-2021-06`) created only when `certificate_arn` is provided
- ECS Fargate cluster, task definition, and service — container port **4001**, health check `GET /health`
- Two IAM roles: `task-execution` (ECS agent pulls image and secrets) and `task` (runtime; gets `ses:SendEmail` when `email_provider = "ses"`)
- RDS PostgreSQL **16** — encrypted, not publicly accessible; backup retention 14 days (prod) / 3 days (non-prod); deletion protection and final snapshot enabled in prod only; storage auto-scales to `max(db_allocated_storage, 100)` GiB
- Secrets Manager: **database secret** (`username`, `password`, `dbname`, `host`, `port`, `DATABASE_URL`) and **app secret** (`JWT_SECRET`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_KEY_ID`, `ENCRYPTION_KEY`, `PASSWORD_PEPPER`)
- RSA 2048-bit key pair (via `tls_private_key`) for RS256 JWT token signing; private key stored in the app secret
- CloudWatch log group `/ecs/<name>` — retention 90 days (prod) / 30 days (non-prod)
- AWS WAF v2 (regional) rate-based rule attached to the ALB; blocks per-IP traffic exceeding `waf_rate_limit` requests in a rolling 5-minute window

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

## Variables

| Name | Type | Default | Description |
|---|---|---|---|
| `aws_account_id` | string | `"344345273019"` | AWS account that this stack is allowed to target. |
| `aws_region` | string | `"us-east-1"` | AWS region for the Identity service. |
| `environment` | string | `"dev"` | Deployment environment name. |
| `project` | string | `"hollis-identity"` | Project/service name used in resource names. |
| `image_tag` | string | `"latest"` | Container image tag deployed by ECS. |
| `certificate_arn` | string | `""` | ACM certificate ARN for HTTPS listener. Leave empty to create HTTP-only dev ALB. |
| `identity_domain_name` | string | `"identity.dev.hollis.health"` | Public host name for the Identity API and JWT issuer (`iss` claim). |
| `reset_password_url` | string | `"https://hollis.health/reset-password"` | Frontend password reset page URL used in password reset emails. Not the Identity API URL. |
| `verify_email_url` | string | `"https://www.hollis.health/verify?type=email"` | Suite email verification page URL used in verification emails. Not the Identity API URL. |
| `cors_origins` | string | `"http://localhost:3000,http://localhost:3001"` | Comma-separated allowed browser origins. |
| `jwt_audiences` | string | `"hollis-health,hollis-workouts"` | Comma-separated JWT audiences (`aud` claim). |
| `email_from` | string | `"noreply@hollis.health"` | Verified SES sender address. |
| `email_provider` | string | `"ses"` | Email backend: `ses` or `console`. |
| `desired_count` | number | `2` | Number of ECS tasks. |
| `cpu` | number | `512` | Fargate task CPU units. |
| `memory` | number | `1024` | Fargate task memory MiB. |
| `db_instance_class` | string | `"db.t4g.micro"` | RDS instance class. |
| `db_allocated_storage` | number | `20` | Initial RDS storage in GiB. Auto-scales up to `max(this, 100)` GiB. |
| `db_multi_az` | bool | `false` | Enable RDS Multi-AZ. Use `true` for staging/prod. |
| `waf_rate_limit` | number | `1000` | ALB WAF per-IP request limit over a rolling 5-minute window. |

## Outputs

| Name | Sensitive | Description |
|---|---|---|
| `aws_account_id` | no | AWS account ID of the caller identity. |
| `ecr_repository_url` | no | ECR URL to push the container image to. |
| `alb_dns_name` | no | <!-- UNVERIFIED: actual DNS name assigned by AWS after apply --> ALB DNS name; use this for Route 53 alias or CNAME. |
| `ecs_cluster_name` | no | ECS cluster name. |
| `ecs_service_name` | no | ECS service name. |
| `database_secret_arn` | yes | ARN of the Secrets Manager secret containing database credentials and `DATABASE_URL`. |
| `app_secret_arn` | yes | ARN of the Secrets Manager secret containing JWT keys, `ENCRYPTION_KEY`, and `PASSWORD_PEPPER`. |

## Provider Requirements

| Provider | Source | Version |
|---|---|---|
| Terraform | — | `>= 1.5.7` |
| `aws` | `hashicorp/aws` | `~> 5.0` |
| `random` | `hashicorp/random` | `~> 3.6` |
| `tls` | `hashicorp/tls` | `~> 4.0` |

## Security Notes

- The RSA private key is generated in Terraform state. Protect state with encryption and restrict access.
- <!-- UNVERIFIED: SES sender identity must be verified in the target AWS account/region before emails can be sent -->
- The `app` Secrets Manager secret stores both the HMAC `JWT_SECRET` and the RSA key pair. Rotate via `terraform apply` after removing the `random_password` / `tls_private_key` resources from state, or use AWS Secrets Manager rotation.
- WAF CloudWatch metrics and sampled requests are enabled for the rate-limit rule and the web ACL as a whole.
