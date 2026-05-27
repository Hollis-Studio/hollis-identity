# ---------------------------------------------------------------------------
# Data source — existing shared RDS instance (read-only reference)
#
# This stack NEVER manages this instance; it only reads its address and port
# so they can be used in the DATABASE_URL secret in main.tf and the additive
# SG rule in network.tf.
#
# The hollis_identity logical database and the hollis_identity Postgres user
# must be created out-of-band before the first apply — see the comment in
# main.tf next to aws_secretsmanager_secret.database.
# ---------------------------------------------------------------------------

data "aws_db_instance" "shared" {
  db_instance_identifier = var.rds_identifier
}
