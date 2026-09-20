# Hollis Identity Infrastructure

Terraform stack for the Identity Service in AWS account `344345273019`,
region `us-east-1`.

Identity **joins the suite's existing shared infrastructure**. An earlier design
gave it a dedicated VPC, ALB, NAT gateways and RDS instance; those resources
were removed and this stack no longer creates any of them. Everything below was
verified against live `aws ... describe` output on 2026-09-20.

## What this stack owns

| Resource | Terraform | Live name |
|---|---|---|
| ECR repository | `aws_ecr_repository.identity` (`main.tf`) | `hollis-identity-prod`, scan on push, MUTABLE tags |
| CloudWatch log group | `aws_cloudwatch_log_group.identity` (`main.tf`) | `/ecs/hollis-identity-prod`, 90-day retention (prod) / 30 (non-prod) |
| Generated secret values | `random_password.{db,jwt_secret,encryption_key,password_pepper}`, `tls_private_key.jwt` (`main.tf`) | — (values live in state; see "Terraform state") |
| Secrets Manager — app bundle | `aws_secretsmanager_secret.app` (`main.tf`) | `hollis-identity-prod/app`: `JWT_SECRET`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_KEY_ID`, `ENCRYPTION_KEY`, `PASSWORD_PEPPER` |
| Secrets Manager — database | `aws_secretsmanager_secret.database` (`main.tf`) | `hollis-identity-prod/database`: `DATABASE_URL` + `username`/`password`/`dbname`/`host`/`port` |
| IAM task execution role | `aws_iam_role.task_execution` (`ecs.tf`) | `hollis-identity-prod-task-execution` (+ inline policy for the three secrets it reads) |
| IAM task role | `aws_iam_role.task` (`ecs.tf`) | `hollis-identity-prod-task` (+ `ses:SendEmail`/`SendRawEmail` when `email_provider = "ses"`) |
| ECS security group | `aws_security_group.ecs` (`network.tf`) | `hollis-identity-prod-ecs` (`sg-08f5c90d26a6048f9`); ingress 4001 from the shared ALB SG only, egress all |
| RDS ingress rule | `aws_security_group_rule.rds_from_identity_ecs` (`network.tf`) | one additive rule on the pre-existing `sg-072f4e44c43356914` |
| ALB target group | `aws_lb_target_group.identity` (`ecs.tf`) | `hollis-identity-prod`, port 4001, `target_type = ip`, health check `GET /health`, 2 up / 3 down |
| ALB listener rule | `aws_lb_listener_rule.identity_host` (`ecs.tf`) | priority **150** on the shared HTTPS listener, host `identity.hollis.health` |
| ECS task definition | `aws_ecs_task_definition.identity` (`ecs.tf`) | family `hollis-identity-prod`, Fargate, awsvpc, container port 4001 |
| ECS service | `aws_ecs_service.identity` (`ecs.tf`) | `hollis-identity-prod` on the shared cluster; 180s health-check grace, deployment circuit breaker with rollback |
| CloudWatch alarms | `monitoring.tf` | `hollis-prod-identity-*` (6 alarms) |
| GitHub Actions deploy role | `github-actions-deploy.tf` | `hollis-identity-prod-github-actions-deploy-role` (OIDC; ECR push + roll the Identity service only) |

## What it reads but never manages

These are referenced through data sources. Removing this stack must not be able
to damage any of them.

| Shared resource | Data source | Owner |
|---|---|---|
| VPC `vpc-0abe755c07479d64a` | `data.aws_vpc.shared` (`network.tf`) | hollis-health-app |
| ALB `hollis-prod-alb` + its HTTPS listener | `data.aws_lb.shared`, `data.aws_lb_listener.https` (`ecs.tf`) | hollis-health-app |
| ECS cluster `hollis-prod-cluster` | `data.aws_ecs_cluster.shared` (`ecs.tf`) | hollis-health-app |
| RDS `hollis-prod-postgres` | `data.aws_db_instance.shared` (`database.tf`) | hollis-health-app |
| SNS `hollis-prod-operational-alerts` | `data.aws_sns_topic.alerts` (`monitoring.tf`) | hollis-health-app |
| Secret `hollis-prod/identity/database-ssl-ca` | `data.aws_secretsmanager_secret.database_ssl_ca` (`ecs.tf`) | created out of band |
| GitHub OIDC provider | `data.aws_iam_openid_connect_provider.github` | hollis-health-app |

`waf.tf` is intentionally empty. The shared ALB carries Health's
`hollis-prod-api-waf`; attaching a second web ACL to the same ALB is not
possible and is not attempted here. Note that the shared ACL's `RateLimitAuth`
rule scopes to URI paths starting with `/auth/`, while Identity's routes are
`/v1/auth/*` — see `ops/README.md` § WAF.

`identity.hollis.health` DNS (Route 53 A alias to the shared ALB) and the ACM
certificate on the shared listener are **not** in this stack. They already exist.

## Out-of-band prerequisites

The shared Postgres instance does not get a database or role from Terraform.
Before the first apply these must exist (see the comment beside
`aws_secretsmanager_secret.database` in `main.tf`):

```sql
CREATE DATABASE hollis_identity;
CREATE USER hollis_identity WITH PASSWORD '<random_password.db.result>';
GRANT ALL PRIVILEGES ON DATABASE hollis_identity TO hollis_identity;
```

## Usage

```bash
terraform init      # S3 backend, no extra flags
terraform plan
terraform apply
```

`terraform.tfvars` is gitignored and already carries the real production values.
`image_tag` has no default and rejects `latest`; pin it to the SHA the service
is actually running before applying.

**Task-definition changes do not reach the running service on their own.**
`aws_ecs_service.identity` ignores `task_definition`, `desired_count` and
`platform_version` because CI rolls the service. Editing `environment`,
`secrets`, `cpu` or `memory` registers a new revision that nothing adopts. The
live drift is visible today: `terraform.tfvars` says `cpu = 512` and
`desired_count = 2`; the service runs cpu 256, desiredCount 1. The procedure for
landing such a change is in `ops/README.md` § "Landing an env or secret change".

Service-level settings (`health_check_grace_period_seconds`,
`deployment_circuit_breaker`) are *not* task-definition attributes and do apply
on apply.

## Terraform state

| | |
| --- | --- |
| Bucket | `hollis-health-tf-state-prod` (versioned, SSE-AES256, public access blocked) |
| Key | `hollis-identity/terraform.tfstate` |
| Locking | DynamoDB `hollis-health-tf-locks-prod` (shared with health and workouts) |

Configured in `versions.tf`; `terraform init` picks it up with no extra flags.
State is **not** kept on a workstation.

State holds `random_password.db`, `random_password.jwt_secret`,
`random_password.encryption_key`, `random_password.password_pepper` and
`tls_private_key.jwt`. If it is lost, the next `apply` regenerates all of them —
rotating the password pepper, which makes every stored password hash
unverifiable. S3 versioning is the only recovery path today. See
`docs/SECRETS-ESCROW.md`.

## Variables

| Name | Type | Default | Description |
|---|---|---|---|
| `aws_account_id` | string | `"344345273019"` | Account this stack is allowed to target (`allowed_account_ids`). |
| `aws_region` | string | `"us-east-1"` | Region. |
| `environment` | string | `"prod"` | Environment name; part of every resource name. |
| `project` | string | `"hollis-identity"` | Service name used in resource names and as the container name. |
| `image_tag` | string | _(required)_ | Immutable image tag (commit SHA) rendered into the task definition. `"latest"` is rejected. |
| `vpc_id` | string | `vpc-0abe755c07479d64a` | Shared VPC. Read only. |
| `private_subnet_ids` | list(string) | 2 subnets | **Unused.** No NAT/VPC endpoints exist, so tasks cannot run here. |
| `public_subnet_ids` | list(string) | 2 subnets | Where ECS tasks actually run (egress via IGW, public IP, ALB-only ingress). |
| `alb_name` | string | `"hollis-prod-alb"` | Shared ALB to attach a listener rule to. |
| `ecs_cluster_name` | string | `"hollis-prod-cluster"` | Shared ECS cluster to join. |
| `rds_identifier` | string | `"hollis-prod-postgres"` | Shared RDS instance to read address/port from. |
| `rds_security_group_id` | string | `sg-072f4e44c43356914` | Pre-existing RDS SG that gets one additive ingress rule. |
| `certificate_arn` | string | ACM ARN | Documentation only — the certificate is already attached to the shared listener. |
| `identity_domain_name` | string | `"identity.hollis.health"` | Host name and JWT issuer (`iss`). |
| `reset_password_url` | string | `https://hollis.health/reset-password` | Frontend reset page used in reset emails. |
| `verify_email_url` | string | `https://www.hollis.health/verify?type=email` | Frontend verification page used in verification emails. |
| `cors_origins` | string | apex, www, admin | Comma-separated allowed browser origins. |
| `jwt_audiences` | string | `"hollis-health,hollis-workouts"` | `aud` values. Must include `hollis-workouts`. |
| `google_client_id` | string | Google OAuth client ID | Expected `aud` for Google id_tokens. Public, not a secret. |
| `apple_service_id` | string | `"com.hollishealth.workouts"` | Native SIWA audience (iOS bundle ID). |
| `apple_web_service_id` | string | `"health.hollis.lifecoach.web"` | Apple web Service ID accepted alongside the native audience. |
| `email_from` | string | `"noreply@hollis.health"` | Verified SES sender. |
| `email_provider` | string | `"ses"` | `ses` or `console`; `console` is rejected by the app in production. |
| `desired_count` | number | `2` | Task count **as rendered**; ignored on the live service (currently 1). |
| `cpu` | number | `512` | Fargate CPU units **as rendered**; live task definition has 256. |
| `memory` | number | `1024` | Fargate memory MiB. |
| `log_level` | string | `"info"` | `LOG_LEVEL` in the container. |
| `sentry_dsn` | string | `""` | Optional. Empty omits `SENTRY_DSN` from the task definition entirely, so Sentry stays off. |
| `alerts_sns_topic_name` | string | `"hollis-prod-operational-alerts"` | Existing SNS topic the alarms publish to. Read only. |
| `alarm_actions_enabled` | bool | `true` | Alarms always evaluate; `false` only suppresses notifications. |
| `alb_latency_p95_threshold_seconds` | number | `2` | p95 latency alarm threshold. |
| `github_deploy_repo` | string | `"Hollis-Studio/hollis-identity"` | Repo allowed to assume the OIDC deploy role. Declared in `github-actions-deploy.tf`. |

## Outputs

| Name | Sensitive | Description |
|---|---|---|
| `aws_account_id` | no | Caller identity account ID. |
| `ecr_repository_url` | no | ECR URL to push the container image to. |
| `target_group_arn` | no | Identity ALB target group ARN. |
| `alb_listener_rule_arn` | no | Identity listener rule ARN (additive — does not touch Health's rules). |
| `ecs_service_name` | no | ECS service name. |
| `database_secret_arn` | yes | Secret holding database credentials and `DATABASE_URL`. |
| `app_secret_arn` | yes | Secret holding JWT keys, `ENCRYPTION_KEY`, `PASSWORD_PEPPER`. |
| `github_actions_deploy_role_arn` | no | ARN to set as the `AWS_DEPLOY_APP_ROLE_ARN` GitHub Actions secret. |
| `alarm_names` | no | The six Identity alarm names. |
| `alerts_sns_topic_arn` | no | SNS topic the alarms publish to. |

## Provider requirements

| Provider | Source | Version |
|---|---|---|
| Terraform | — | `>= 1.5.7` |
| `aws` | `hashicorp/aws` | `~> 5.0` |
| `random` | `hashicorp/random` | `~> 3.6` |
| `tls` | `hashicorp/tls` | `~> 4.0` |

## Security notes

- **Production signs tokens with HS256**, not RS256. `ecs.tf` sets
  `JWT_ALGORITHM = "HS256"`. The RSA key pair (`tls_private_key.jwt`) is still
  generated and stored in the app secret as an unused fallback, which is why the
  `tls` provider is still required. `/.well-known/jwks.json` therefore returns
  an empty key set in production.
- `PASSWORD_PEPPER`, `JWT_SECRET` and `ENCRYPTION_KEY` exist only inside
  Terraform state. There is no escrow. Read `docs/SECRETS-ESCROW.md` before any
  state surgery, `terraform taint`, or removal of a `random_password` resource.
- Rotating `JWT_SECRET` also breaks the Workouts API: its task definition
  carries the same value as `IDENTITY_JWT_SECRET` and it verifies Identity
  tokens locally. Rotate both together.
- `ecs:UpdateService` on the deploy role is scoped to the Identity service ARN
  (`service/hollis-prod-cluster/hollis-identity-prod`). `RegisterTaskDefinition`
  and `DescribeTaskDefinition` do not support resource-level permissions and
  remain on `*`.
- The SES sender identity must stay verified in `us-east-1` or password reset
  and email verification silently stop delivering.
