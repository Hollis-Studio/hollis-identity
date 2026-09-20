# Operations — Hollis Identity Service

This runbook covers deployment, database migrations, secret management,
monitoring and routine operational tasks for `hollis-identity`.

Every AWS name below was verified against live `aws ... describe` output on
2026-09-20. Where an earlier version of this file guessed, the guess is gone
rather than marked `UNVERIFIED`.

---

## Infrastructure overview

Terraform in `infrastructure/` **joins existing shared infrastructure**. It does
not own a VPC, an ALB, an RDS instance or a WAF — an earlier standalone design
did, and those resources were removed. See `infrastructure/README.md` for the
resource-by-resource split.

What this stack creates:

| Resource | Live value |
|---|---|
| ECR repository | `hollis-identity-prod` (scan on push, MUTABLE tags) |
| ECS task definition + service | family/service `hollis-identity-prod` on the **shared** cluster `hollis-prod-cluster` |
| ALB target group | `hollis-identity-prod`, port 4001, health check `GET /health` |
| ALB listener rule | priority **150** on the shared `hollis-prod-alb` HTTPS listener, host `identity.hollis.health` (Health uses 100, Workouts 200, default → Health API) |
| ECS security group | `hollis-identity-prod-ecs`; ingress 4001 from the ALB SG only |
| RDS ingress rule | one additive rule on the existing `sg-072f4e44c43356914` |
| Secrets Manager | `hollis-identity-prod/app` and `hollis-identity-prod/database` |
| CloudWatch log group | `/ecs/hollis-identity-prod`, 90-day retention |
| CloudWatch alarms | `hollis-prod-identity-*` (see "Monitoring") |

What it reads but never manages: VPC `vpc-0abe755c07479d64a`, ALB
`hollis-prod-alb`, cluster `hollis-prod-cluster`, RDS `hollis-prod-postgres`,
the `hollis-prod-operational-alerts` SNS topic, and the ACM certificate on the
shared listener.

Target: AWS account `344345273019`, region `us-east-1`.

---

## Prerequisites

- Terraform >= 1.5.7 (pinned in `infrastructure/versions.tf`)
- AWS credentials for account `344345273019` with ECS/ECR/Secrets Manager/IAM
  and read access to the shared networking resources
- Docker with BuildKit (for local container builds)
- An npmrc carrying a GitHub Packages `read:packages` token for the
  `@hollis-studio` scope — see "Container build" for the exact file format

---

## Terraform — plan and apply

State lives in the shared S3 backend (bucket `hollis-health-tf-state-prod`, key
`hollis-identity/terraform.tfstate`, DynamoDB lock table
`hollis-health-tf-locks-prod`), configured in `infrastructure/versions.tf`.
There is nothing to configure per-environment and nothing kept on a workstation.

```bash
cd infrastructure
terraform init      # picks up the S3 backend with no extra flags
terraform plan
terraform apply
```

`infrastructure/terraform.tfvars` is gitignored and already holds the real
production values. `image_tag` has no default and rejects `latest`; set it to
the SHA the service is actually running before applying, or Terraform will
render a task definition pointing at an older image.

CI never runs Terraform. The GitHub Actions role
(`infrastructure/github-actions-deploy.tf`) can push to the Identity ECR repo,
register task definitions and update **only** the Identity service — it has no
infra-provisioning permissions.

---

## Deployment

Normal path: **push to `main`.** `.github/workflows/deploy.yml` builds the
image, pushes it to ECR, clones the live task definition with only the image
swapped, and rolls the service. It runs the shared check suite
(`.github/workflows/checks.yml`) first and will not deploy if those fail.

Re-deploy an already-built tag (emergency rollback) with
`workflow_dispatch` + `image_tag`; that path intentionally skips the checks so a
red test suite cannot block a rollback.

### The `ignore_changes = [task_definition]` trap

**Editing `environment`, `secrets`, `cpu` or `memory` in
`infrastructure/ecs.tf` and running `terraform apply` does NOT change the
running service.** This is the single most expensive thing to get wrong here,
and it is invisible: `terraform apply` reports success and `terraform plan`
then reports no changes.

Two mechanisms combine:

1. `aws_ecs_service.identity` has
   `lifecycle { ignore_changes = [desired_count, task_definition, platform_version] }`.
   Terraform registers a **new task definition revision** with your change, then
   deliberately does not point the service at it — otherwise it would drag the
   service back off whatever revision CI last rolled.
2. `deploy.yml` renders the **currently-deployed** task definition
   (`aws ecs describe-task-definition --task-definition hollis-identity-prod`,
   i.e. the family's latest ACTIVE revision) and swaps only the image. Because
   step 1 registered a newer revision, a deploy *can* pick the change up — but
   only if no further Terraform apply or CI deploy has registered a revision
   since, and nothing guarantees the ordering.

You can see the drift today: `terraform.tfvars` sets `cpu = 512` and
`desired_count = 2`, while the live service runs **cpu 256, desiredCount 1**.

#### Landing an env or secret change

```bash
# 0. Confirm what is actually live before and after.
aws ecs describe-task-definition --task-definition hollis-identity-prod \
  --query 'taskDefinition.{rev:revision,cpu:cpu,memory:memory,env:containerDefinitions[0].environment,secrets:containerDefinitions[0].secrets[].name}'

# 1. Make the change in infrastructure/ecs.tf (or the relevant tfvars value)
#    and apply it. This registers a new revision; the service does not move.
cd infrastructure && terraform apply

# 2. Note the revision Terraform registered.
aws ecs describe-task-definition --task-definition hollis-identity-prod \
  --query 'taskDefinition.revision'

# 3. Point the service at it explicitly. This is the step that actually lands
#    the change — do it immediately after step 1 so no CI deploy interleaves.
aws ecs update-service --cluster hollis-prod-cluster \
  --service hollis-identity-prod \
  --task-definition hollis-identity-prod:<REV> \
  --force-new-deployment

# 4. Wait for steady state and confirm the new value is live.
aws ecs wait services-stable --cluster hollis-prod-cluster --services hollis-identity-prod
aws ecs describe-services --cluster hollis-prod-cluster --services hollis-identity-prod \
  --query 'services[0].taskDefinition'
curl -sS https://identity.hollis.health/health
```

The next CI deploy clones whatever revision is live at that point, so once step
3 has landed, the change survives subsequent image-only deploys.

A **secret value** change (rotating `JWT_SECRET`, `PASSWORD_PEPPER`, the DB
password) does not need a new revision at all — the task definition references
`secretsmanager` ARNs, and the ECS agent resolves them at task start. Put the
new value in Secrets Manager, then force a new deployment so tasks re-read it.
Read "Rotating secrets" below first: some of these values cannot be rotated
without invalidating data.

---

## Container build

The Dockerfile is a three-stage build on a SHA-pinned `node:22-alpine` base and
produces a **non-root** image (uid/gid 1001 `identity:nodejs`). It needs a
BuildKit secret named `npmrc` for GitHub Packages access.

That secret must be a real **npmrc** — scope mapping plus token:

```
@hollis-studio:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=<read:packages token>
```

`.env.npm.local` in this repo is **not** usable for this. It is an env-var file
(`NODE_AUTH_TOKEN=...`), and passing it produces
`npm error code E401 ... authentication token not provided`, because npm reads
it as config keys it does not recognise. The committed `./.npmrc` is equally
unusable inside the build: it references `${NODE_AUTH_TOKEN}`, which is unset in
the build sandbox. `deploy.yml` writes a correct file to `/tmp/npmrc-ci` from
the `NODE_AUTH_TOKEN` Actions secret; locally, keep one at
`~/.config/hollis/npmrc-with-token` (mode 600) as the Workouts server does.

```bash
DOCKER_BUILDKIT=1 docker build \
  --secret id=npmrc,src="$HOME/.config/hollis/npmrc-with-token" \
  -t hollis-identity:local .
```

Pushing by hand is not the normal path — CI pushes both `:<sha>` and `:latest`
to `344345273019.dkr.ecr.us-east-1.amazonaws.com/hollis-identity-prod`.

---

## Database migrations

**Migrations are not manual.** The container CMD runs
`./node_modules/.bin/prisma migrate deploy` and only then starts the server, so
committed migrations are applied on every task start, before the task can pass
a health check. Prisma serialises concurrent `migrate deploy` invocations, so a
rolling deployment with two tasks is safe.

Consequences worth internalising:

- A bad migration presents as **tasks that never become healthy**, not as a
  running service with a wrong schema. The ECS deployment circuit breaker
  (enabled in `ecs.tf`) rolls the service back to the last revision that
  reached steady state, and the ALB keeps serving the old tasks throughout.
- The service's `health_check_grace_period_seconds = 180` exists to cover
  migrate + boot. Do not set it back to 0.
- Migrations are **not** reversible by redeploying an older image: the old
  image simply finds nothing pending. Rolling a schema change back needs a new
  forward migration.

```bash
# Local development
npm run prisma:migrate         # prisma migrate dev (creates migrations)
npm run prisma:generate        # regenerate the client after schema edits

# Apply pending migrations by hand (rarely needed; the container does this)
DATABASE_URL=<identity url> npm run prisma:migrate:deploy
```

CI applies the migrations to a throwaway Postgres service container on every
run (`.github/workflows/checks.yml`), which is what catches a migration that no
longer applies from empty.

---

## Secret management

| Secret | Contents |
|---|---|
| `hollis-identity-prod/app` | `JWT_SECRET`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_KEY_ID`, `ENCRYPTION_KEY`, `PASSWORD_PEPPER` |
| `hollis-identity-prod/database` | `DATABASE_URL`, plus `username`, `password`, `dbname`, `host`, `port` |

The task definition pulls individual JSON fields via `secrets[].valueFrom`
(`<arn>:<KEY>::`). No secret value is ever an `environment` entry.

All of these values are generated by `random_password` / `tls_private_key` in
`infrastructure/main.tf`, which means **Terraform state is the only copy**.
Read `docs/SECRETS-ESCROW.md` before touching them — losing or regenerating
`PASSWORD_PEPPER` makes every stored password hash unverifiable, and there is
currently no escrow.

### Rotating secrets

Blast radius differs enormously per value:

| Value | Effect of rotation |
|---|---|
| `JWT_SECRET` | Every issued token fails verification immediately. Access tokens live **90 days** and refresh tokens **365 days** (`ACCESS_TOKEN_EXPIRY` / `REFRESH_TOKEN_EXPIRY` in `src/services/authService.ts`), so this force-logs-out every user on every app with no grace period. It also breaks the Workouts server, which verifies Identity tokens locally with a copy of this secret — rotate both together or Workouts returns 401 for everything. |
| `ENCRYPTION_KEY` | Stored TOTP secrets become undecryptable; every MFA-enrolled user must re-enrol. |
| `PASSWORD_PEPPER` | **Every password hash becomes unverifiable.** Nobody can log in with a password again; the only recovery is a forced reset for all users. Treat as unrecoverable data loss. |
| `JWT_PRIVATE_KEY` / `JWT_KEY_ID` | Inert today — production runs `JWT_ALGORITHM=HS256` and the RS256 material is an unused fallback. |
| Database password | Must be changed in Postgres and in the secret, then tasks restarted. |

```bash
# Values are rotated in Secrets Manager, not by `terraform apply` — an apply
# that regenerates a random_password rewrites the secret with a new value.
aws secretsmanager put-secret-value --secret-id hollis-identity-prod/app \
  --secret-string '<full JSON object with all six keys>'

# Then restart tasks so the ECS agent re-resolves the secret.
aws ecs update-service --cluster hollis-prod-cluster \
  --service hollis-identity-prod --force-new-deployment
```

`put-secret-value` replaces the whole JSON document; omitting a key deletes it
and the next task start fails with a secret-resolution error.

---

## ECS operations

```bash
# Force a new deployment (re-read secrets, replace tasks)
aws ecs update-service --cluster hollis-prod-cluster \
  --service hollis-identity-prod --force-new-deployment

# Running tasks
aws ecs list-tasks --cluster hollis-prod-cluster \
  --service-name hollis-identity-prod

# Recent service events (first place to look on a failed deploy)
aws ecs describe-services --cluster hollis-prod-cluster \
  --services hollis-identity-prod --query 'services[0].events[:10]'

# Scale
aws ecs update-service --cluster hollis-prod-cluster \
  --service hollis-identity-prod --desired-count 2
```

`desired_count` is in `ignore_changes`, so scaling via the CLI is the real
control and Terraform will not fight it. Keep it at >= 2 for rolling deploys
without a gap; it is currently 1.

---

## Health checks

The ALB target group polls `GET /health` on port 4001 every 30 seconds. The
endpoint performs a live database ping (`SELECT 1`):

- `200 { ok: true, service: "hollis-identity", db: "ok" }` — healthy
- `503 { ok: false, service: "hollis-identity", db: "unreachable" }` — DB
  connection failed; the ALB drains the target and ECS replaces the task

Thresholds: 2 consecutive successes → healthy; 3 consecutive failures →
unhealthy. The container also carries a Docker `HEALTHCHECK`, which ECS ignores
(the task definition declares no container health check) but which makes
`docker run` locally self-describing.

---

## Monitoring

`infrastructure/monitoring.tf` defines six alarms, all publishing to the
existing `hollis-prod-operational-alerts` SNS topic:

| Alarm | Fires when |
|---|---|
| `hollis-prod-identity-no-healthy-hosts` | target group healthy host count < 1 for 1 minute |
| `hollis-prod-identity-task-count-low` | ECS `LiveTaskCount` < 1 for 3 minutes |
| `hollis-prod-identity-cpu-high` | service CPU >= 80% for 15 minutes |
| `hollis-prod-identity-memory-high` | service memory >= 90% for 10 minutes |
| `hollis-prod-identity-target-5xx` | > 5 target 5xx responses in 5 minutes |
| `hollis-prod-identity-latency-high` | p95 target response time > 2s for 15 minutes |

**The `hollis-prod-` name prefix is load-bearing.** Both the SNS topic policy
and its KMS key policy allow `cloudwatch.amazonaws.com` only for alarm ARNs
matching `arn:aws:cloudwatch:us-east-1:344345273019:alarm:hollis-prod-*`. An
alarm named `hollis-identity-prod-…` would be created, would evaluate, would go
to ALARM — and the notification would be dropped silently at the topic. Do not
"tidy" the prefix to match `local.name`.

Alarms use `AWS/ECS` and `AWS/ApplicationELB`, never `ECS/ContainerInsights`:
Container Insights is **disabled** on `hollis-prod-cluster`, so Insights metrics
have no datapoints there.

```bash
# Are the alarms present and in OK?
aws cloudwatch describe-alarms --alarm-name-prefix hollis-prod-identity \
  --query 'MetricAlarms[].{n:AlarmName,s:StateValue,e:ActionsEnabled}'

# Does the topic have anyone listening?
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:344345273019:hollis-prod-operational-alerts
```

There is no synthetic canary for `identity.hollis.health`. Health has canaries
for its own endpoints; Identity has none, so a total outage is detected via
`no-healthy-hosts` rather than from outside the VPC.

---

## Log access

CloudWatch log group: `/ecs/hollis-identity-prod` (90-day retention).

```bash
aws logs tail /ecs/hollis-identity-prod --follow

aws logs filter-log-events --log-group-name /ecs/hollis-identity-prod \
  --filter-pattern '"[SECURITY]"'

aws logs filter-log-events --log-group-name /ecs/hollis-identity-prod \
  --filter-pattern '"[MFA]"'
```

All logs are structured JSON (Pino). Each request log includes `requestId`,
which also appears in the `X-Request-Id` response header and in JSON error
bodies — use it to correlate a client-reported error with server logs.

---

## Token revocation runbook

### Revoke a single user's sessions (e.g. account compromise)

`denyAllUserAccessTokens` writes a watermark to `UserTokenDenylistEntry`; all
access tokens issued at or before the watermark are rejected. Refresh tokens
must be revoked separately in `RefreshToken`.

**This does not reach the Workouts API.** The Workouts server verifies Identity
tokens locally with a copy of the HS256 secret rather than calling `/verify`, so
a revoked access token keeps working against Workouts until it expires — up to
90 days. Identity-side revocation covers Identity and the Health API only.

```sql
-- Revoke all refresh tokens for a user
UPDATE "RefreshToken"
SET "revokedAt" = NOW(), "revokedReason" = 'admin_action'
WHERE "userId" = '<user-id>'
  AND "revokedAt" IS NULL;

-- Insert a user-level access token denylist entry
-- expiresAt must outlive every token the watermark covers: ACCESS_TOKEN_EXPIRY
-- (90d, ACCESS_TOKEN_EXPIRY in src/services/authService.ts) plus the 5-minute clock-skew margin used
-- by userDenylistEntryExpiresAt() in src/services/tokenDenylistService.ts. A
-- shorter value silently un-revokes those tokens once the 60s cleanup reaps the
-- row. Keep in step with ACCESS_TOKEN_EXPIRY_MS if the lifetime changes.
INSERT INTO "UserTokenDenylistEntry" ("id", "userId", "deniedBefore", "reason", "expiresAt")
VALUES (gen_random_uuid(), '<user-id>', NOW(), 'admin_action', NOW() + INTERVAL '90 days 5 minutes')
ON CONFLICT ("userId") DO UPDATE
  SET "deniedBefore" = NOW(),
      "reason" = 'admin_action',
      "expiresAt" = NOW() + INTERVAL '90 days 5 minutes',
      "revokedAt" = NOW();
```

### Clear expired denylist entries manually

```sql
DELETE FROM "AccessTokenDenylistEntry" WHERE "expiresAt" < NOW();
DELETE FROM "UserTokenDenylistEntry"   WHERE "expiresAt" < NOW();
```

The service also runs automatic cleanup on a 1-minute interval via
`store.startCleanupTimer()`.

`UserTokenDenylistEntry` rows written before the watermark-expiry fix carry an
already-lapsed 15-minute `expiresAt` and have been reaped, so any password reset
or change performed before that deploy lost its revocation and is not repaired
retroactively — users who reset a password believing it ended their other
sessions need to reset again.

---

## WAF

**Identity has no WAF of its own**, and Identity's routes are not covered by the
shared one in any useful way. `infrastructure/waf.tf` is deliberately empty: the
standalone Identity ALB and its WAF were removed, and the shared
`hollis-prod-alb` carries Health's `hollis-prod-api-waf`, which Health owns.

The gap to know about: that ACL's `RateLimitAuth` rule scopes its rate limit to
URI paths **starting with** `/auth/`, and every Identity auth route is mounted
under `/v1/auth/*`. So the rule never matches Identity traffic. Identity's
distributed-abuse protection today is entirely its own application rate
limiters (`loginRateLimiter`, `loginEmailRateLimiter`,
`authSessionRateLimiter`), which are Postgres-backed and shared across tasks —
the opposite of the previous claim in this file that WAF was primary and the app
limiters were defence in depth.

Closing it needs a change in `hollis-health-app`'s WAF module (add `/v1/auth/`
to the scope-down statement, or make it a regex/`CONTAINS` match), not here.

---

## SES email setup

Email delivery uses AWS SES when `EMAIL_PROVIDER=ses` (production value).
`EMAIL_PROVIDER=console` is rejected at startup in production.

Sender: `noreply@hollis.health`, region `us-east-1`. The ECS task role receives
`ses:SendEmail` / `ses:SendRawEmail` via Terraform when
`email_provider = "ses"`.

If reset or verification emails stop arriving, check in this order: SES identity
still verified; account out of the SES sandbox; `AWS_REGION` matches the region
holding the verified identity; `RESET_PASSWORD_URL` / `VERIFY_EMAIL_URL` point
at frontend pages, not the Identity API.

---

## DNS and TLS

Already provisioned — nothing to do unless the ALB is replaced.

- `identity.hollis.health` is a Route 53 **A alias** to
  `hollis-prod-alb-414971130.us-east-1.elb.amazonaws.com`
- TLS terminates on the shared ALB's HTTPS listener using ACM certificate
  `89bb25b7-f69d-4af5-a6f1-fe226161eb2a`, which Health owns and attached. This
  stack only adds listener rule 150; it never touches the listener or its
  certificates.

---

## Local development quick reference

```bash
npm install                 # needs a GitHub Packages token for @hollis-studio
npm run prisma:generate
npm run prisma:migrate      # against a local Postgres
npm run dev                 # tsx watch, port 4001
npm run typecheck
npm run build
npm test                    # expects Postgres at localhost:5432 (test/test/test)
```

The app does not auto-load `.env`; export it first:

```bash
set -a && source .env && set +a
npm run dev
```

Secret-shaped env vars are validated at startup: `JWT_SECRET` and
`ENCRYPTION_KEY` must be at least 32 characters with mixed character classes
(`openssl rand -base64 32` produces an acceptable value), and in production
`EMAIL_PROVIDER` must be `ses`.
