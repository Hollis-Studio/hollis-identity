# Identity secrets: single-copy risk and break-glass escrow

**Status:** the risk is real and open. The escrow procedure below is a proposal
awaiting Isaac's approval; nothing in it has been executed.

No secret value appears in this document, and none should ever be pasted into
one. Everything here is designed so that values move directly from AWS into a
password manager without passing through a file, a terminal transcript, a chat
message or an agent's context.

---

## The risk in one paragraph

Three values decide whether Hollis accounts can be used at all:
`PASSWORD_PEPPER`, `JWT_SECRET` and `ENCRYPTION_KEY`. All three are *generated*
by Terraform (`random_password` in `infrastructure/main.tf`) and written to one
Secrets Manager secret. Terraform state is the authority for what they are. If
that state is lost, rolled back, or a `random_password` resource is removed from
it, the next `terraform apply` **generates new values and overwrites the
secret** — and for `PASSWORD_PEPPER` that is unrecoverable data loss: every
stored bcrypt hash was computed with the old pepper and can never be verified
again. No user could log in with a password, ever, and the only remedy would be
a forced password reset for the entire user base.

## Verified state of the copies (2026-09-20)

| Copy | Status |
|---|---|
| Terraform state object `hollis-identity/terraform.tfstate` in `hollis-health-tf-state-prod` | Present. Bucket versioning **Enabled**, no lifecycle rule expiring noncurrent versions, SSE enabled. **But the object has exactly 1 version** — the state moved to this backend recently, so versioning currently offers zero rollback depth. |
| Object Lock / MFA delete on the state bucket | **Not configured.** A delete-object call with a version id is permanent. |
| Secrets Manager `hollis-identity-prod/app` | Present, encrypted with the AWS-managed key, **1 version total** (`AWSCURRENT`, created 2026-05-26, never changed). No `AWSPREVIOUS`, so no in-service fallback if it is overwritten. Rotation not configured. |
| Any copy outside AWS | **None.** |

So: two copies exist (state and Secrets Manager), but they are not independent —
Terraform owns both, one `apply` writes both, and neither has usable history.

## How this actually fails

Ranked by how plausible each is for a one-person, agent-driven operation:

1. **An apply from an uninitialised working copy.** Someone (or an agent) runs
   `terraform apply` in `infrastructure/` before `terraform init` has attached
   the S3 backend, or with a stale local state file. Terraform sees no
   `random_password` in state, generates fresh values, and pushes a new secret
   version. Every password on the platform becomes unverifiable. The apply
   reports success.
2. **A resource removed, tainted or replaced.** `terraform taint`,
   `-replace=random_password.password_pepper`, or deleting the resource block to
   "clean up" the unused RS256 material and catching the pepper in the blast
   radius.
3. **State object deleted or corrupted.** No Object Lock, one version, and the
   bucket is shared with two other stacks whose agents also write to it.
4. **Account-level loss.** Bucket deleted, region issue, credentials revoked —
   at which point there is nothing outside AWS to restore from.

## Blast radius per value

| Value | If the value is lost / regenerated |
|---|---|
| `PASSWORD_PEPPER` | **Unrecoverable.** Every `User.passwordHash` was computed over `password + pepper`. Password login fails for all users, permanently. Only remedy: force-reset every account (which itself needs working email delivery). |
| `JWT_SECRET` | Recoverable but disruptive. Every issued token fails verification at once: access tokens are 90-day and refresh tokens 365-day (`ACCESS_TOKEN_EXPIRY` / `REFRESH_TOKEN_EXPIRY` in `src/services/authService.ts`), so there is no grace period — every user on every app is signed out. Also breaks the Workouts API, whose task definition carries the same value as `IDENTITY_JWT_SECRET` and verifies Identity tokens locally. |
| `ENCRYPTION_KEY` | Recoverable but disruptive. Stored TOTP secrets become undecryptable; every MFA-enrolled user must re-enrol, and step-up/MFA-gated actions fail until they do. |
| `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` / `JWT_KEY_ID` | No impact today. Production signs with HS256; this RSA material is an unused fallback. |
| Database password | Recoverable. Reset the Postgres role and update the secret. |

Note the asymmetry: two of these are "everyone gets logged out", which is bad.
One of them is "nobody can ever log in again", which is a different category
and is the reason this document exists.

---

## Proposed escrow — for Isaac's approval

Four parts. Parts 1 and 2 are the escrow itself; 3 and 4 stop the escrow from
being needed. None of this changes how the service runs.

### Part 1 — Offline break-glass envelope (do this first)

The only copy that survives an AWS-side mistake is one that is not in AWS.

Isaac runs these commands himself, on his own machine, and pastes each value
straight into a 1Password (or equivalent) item named
**"Hollis Identity — break-glass secrets"**. One field per key. Do not save the
output to a file, do not run this inside an agent session, and close the
terminal afterwards.

```bash
# Prints the app secret bundle. Six keys: JWT_SECRET, JWT_PRIVATE_KEY,
# JWT_PUBLIC_KEY, JWT_KEY_ID, ENCRYPTION_KEY, PASSWORD_PEPPER.
aws secretsmanager get-secret-value \
  --secret-id hollis-identity-prod/app \
  --query SecretString --output text
```

Record alongside it, in the same item:

- the date
- the Secrets Manager version id that was current
  (`aws secretsmanager list-secret-version-ids --secret-id hollis-identity-prod/app`)
- a **fingerprint** of each value, so the escrow can be checked later without
  revealing anything (see Part 2)

Add the same treatment for the database secret
(`hollis-identity-prod/database`) while there.

### Part 2 — Fingerprints, so the escrow is verifiable

A copy nobody has verified is not a backup. Fingerprints let anyone confirm the
envelope still matches production without exposing a value, and they are safe to
paste into a runbook, a board post or a commit message.

```bash
# Prints a SHA-256 per key, never the value itself.
aws secretsmanager get-secret-value --secret-id hollis-identity-prod/app \
  --query SecretString --output text \
| python3 -c '
import hashlib, json, sys
d = json.load(sys.stdin)
for k in sorted(d):
    print(k, hashlib.sha256(d[k].encode()).hexdigest()[:16])
'
```

Run it quarterly and after any rotation. If a fingerprint changes and nobody
intended a rotation, something overwrote the secret — investigate before the
old value ages out of `AWSPREVIOUS`.

### Part 3 — Make Terraform stop being the authority (needs review)

Recommended change, **not applied** (`main.tf` secret resources are deliberately
untouched here):

- Add `lifecycle { prevent_destroy = true }` to
  `aws_secretsmanager_secret.app`, `aws_secretsmanager_secret.database`, and to
  the four `random_password` resources. This turns the most likely accident
  (item 1 and 2 above) into a plan-time error instead of a silent rewrite.
- Add `lifecycle { ignore_changes = [secret_string] }` to
  `aws_secretsmanager_secret_version.app`, so a regenerated `random_password`
  can no longer overwrite the live secret even if state is lost. Secrets Manager
  then becomes the system of record and Terraform only creates the secret once.
- Longer term, stop generating these in Terraform at all: create the values once
  by hand, and have Terraform read the ARN via
  `data.aws_secretsmanager_secret`. The values then have no representation in
  state.

The tradeoff is explicit: `prevent_destroy` means a genuine teardown needs a
deliberate two-step (remove the lifecycle block, then destroy), and
`ignore_changes` means a deliberate rotation is a `put-secret-value` call rather
than an `apply`. Both are the right way round for values whose loss is
unrecoverable.

### Part 4 — Protect the state object

- Enable S3 **Object Lock** (governance mode) or at minimum a bucket policy
  denying `s3:DeleteObjectVersion` on `hollis-identity/terraform.tfstate*` to
  everything except a break-glass principal.
- Keep versioning on and never add a lifecycle rule that expires noncurrent
  versions of the state prefix.
- The bucket is shared with the Health and Workouts stacks, so this change
  belongs to whoever owns that bucket — coordinate rather than applying it from
  this repo.

---

## If it has already happened

Symptom: users report "wrong password" en masse, or
`aws secretsmanager list-secret-version-ids` shows a version created at a time
nobody intended a rotation.

1. **Stop deployments immediately.** Do not run `terraform apply` again — a
   second apply can push the wrong value into `AWSPREVIOUS` and destroy the last
   in-service copy.
2. Check for an `AWSPREVIOUS` stage on `hollis-identity-prod/app`. If present,
   its value is the old bundle; `put-secret-value` it back as `AWSCURRENT` and
   force a new ECS deployment.
3. If not, restore the previous version of the state object
   (`aws s3api list-object-versions --bucket hollis-health-tf-state-prod
   --prefix hollis-identity/terraform.tfstate`) and read the value from there.
   **As of 2026-09-20 there is only one version, so this path does not exist
   yet.**
4. If neither copy exists and Part 1 was never done: the pepper is gone.
   Communicate a mandatory password reset, and confirm SES delivery is healthy
   before announcing it — the reset flow depends on it.
