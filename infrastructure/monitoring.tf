# ---------------------------------------------------------------------------
# CloudWatch alarms — Identity
#
# Identity had ZERO alarms before this file: if the single task died or the
# target group went empty, nothing told anyone. Every Hollis app depends on
# Identity for login, so it is the highest-blast-radius service in the suite.
#
# Notifications go to the EXISTING hollis-prod-operational-alerts SNS topic,
# owned by hollis-health-app (infrastructure/aws/modules/monitoring/main.tf).
# It is referenced read-only through a data source — this stack never creates,
# modifies or subscribes to it.
#
# ===========================================================================
# ALARM NAMING IS LOAD-BEARING — DO NOT "TIDY" THE PREFIX
# ===========================================================================
# Both gates on the alert path allow cloudwatch.amazonaws.com only for alarms
# whose ARN matches `arn:aws:cloudwatch:us-east-1:344345273019:alarm:hollis-prod-*`:
#
#   1. the SNS topic policy statement AllowCloudWatchAlarmPublish
#      (ArnLike aws:SourceArn), and
#   2. the topic's KMS key policy statement AllowCloudWatchAlarmEncryption
#      (key 22d7364a-cbaa-41bd-a38e-28e9407005e3, same ArnLike condition).
#
# Verified against live `aws sns get-topic-attributes` and
# `aws kms get-key-policy` output on 2026-09-20.
#
# Names built from local.name would be `hollis-identity-prod-*`, which matches
# NEITHER condition. Those alarms would still be created, still evaluate, and
# still go to ALARM — and the notification would be dropped at the topic. That
# failure is invisible from the alarm's own state, which is exactly how a
# sibling service ended up with alarms nobody knew were dead. Hence
# local.alarm_prefix below, which yields `hollis-prod-identity-*`.
#
# Widening the health-owned policies instead would be the cleaner fix, but that
# file belongs to hollis-health-app; matching the existing prefix needs no
# cross-repo change.
# ---------------------------------------------------------------------------

locals {
  alarm_prefix = "hollis-${var.environment}-identity"
}

data "aws_sns_topic" "alerts" {
  name = var.alerts_sns_topic_name
}

# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

# Dimensions come from the resource/data attributes, not hand-written strings:
# CloudWatch wants the ARN *suffix* form (`app/<name>/<id>`,
# `targetgroup/<name>/<id>`), and a full ARN or a bare name matches no metric.
# Confirmed live: `aws cloudwatch list-metrics --namespace AWS/ApplicationELB
# --dimensions Name=TargetGroup,Value=targetgroup/hollis-identity-prod/f88dafa2fb9d30ef
# Name=LoadBalancer,Value=app/hollis-prod-alb/c0f7405513aab2ff` returns
# HealthyHostCount and TargetResponseTime.
resource "aws_cloudwatch_metric_alarm" "no_healthy_hosts" {
  alarm_name          = "${local.alarm_prefix}-no-healthy-hosts"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Identity has no healthy targets behind the shared ALB — login is down for every Hollis app. Check `aws ecs describe-services --cluster ${var.ecs_cluster_name} --services ${local.name}` events and /ecs/${local.name} logs."

  dimensions = {
    TargetGroup  = aws_lb_target_group.identity.arn_suffix
    LoadBalancer = data.aws_lb.shared.arn_suffix
  }

  # Missing data here means the target group reported nothing at all, which is
  # not "fine" for a service that is supposed to have running tasks.
  treat_missing_data = "breaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

# AWS/ECS LiveTaskCount is emitted by the service itself once a minute and does
# NOT require Container Insights — which matters, because Container Insights is
# `disabled` on hollis-prod-cluster (verified with
# `aws ecs describe-clusters --include SETTINGS`). Any alarm written against the
# ECS/ContainerInsights namespace for this cluster would never receive a single
# datapoint.
#
# Verified live: `aws cloudwatch list-metrics --namespace AWS/ECS --dimensions
# Name=ServiceName,Value=hollis-identity-prod` returns exactly LiveTaskCount,
# CPUUtilization and MemoryUtilization, and LiveTaskCount had 60 datapoints in
# the last hour at period 60.
#
# LiveTaskCount counts tasks in any lifecycle state, so it can read >= 1 while a
# replacement task is still PROVISIONING. The no-healthy-hosts alarm above is
# the one that speaks to "can it serve"; this one catches "the service lost its
# tasks and is not getting them back".
resource "aws_cloudwatch_metric_alarm" "task_count_low" {
  alarm_name          = "${local.alarm_prefix}-task-count-low"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "LiveTaskCount"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Identity ECS service has no live tasks for 3 minutes — container crash loop or a failed deployment. Runbook: ops/README.md."

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = local.name
  }

  treat_missing_data = "breaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

# ---------------------------------------------------------------------------
# Saturation
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.alarm_prefix}-cpu-high"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Identity CPU at or above 80% of its ${var.cpu}-unit reservation for 15 minutes. Password hashing is CPU-bound (bcrypt, BCRYPT_COST_FACTOR default 13), so sustained load shows up as slow logins before it shows up as errors."

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = local.name
  }

  # A service with no tasks emits nothing; that is the task-count alarm's job,
  # not this one's.
  treat_missing_data = "notBreaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "${local.alarm_prefix}-memory-high"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  alarm_description   = "Identity memory at or above 90% of its ${var.memory} MiB reservation for 10 minutes — the container is close to an OOM kill."

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = local.name
  }

  treat_missing_data = "notBreaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

# ---------------------------------------------------------------------------
# Errors and latency
# ---------------------------------------------------------------------------

# Raw count, not an error *rate*. Identity serves a low, bursty request volume,
# so a rate alarm is dominated by the denominator: two requests, one 5xx, and a
# 5%-rate alarm fires at 50%. A Sum threshold is the honest signal at this
# traffic level. Revisit if request volume grows by an order of magnitude —
# hollis-health-app's api_5xx alarm shows the metric-math rate form.
#
# HTTPCode_Target_5XX_Count has no datapoints for this target group today,
# because the service has never returned a target 5xx. That is why
# treat_missing_data is notBreaching: ALB error-count metrics are sparse by
# nature and only materialise on the first error.
resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${local.alarm_prefix}-target-5xx"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Identity returned more than 5 target 5xx responses in 5 minutes. /health failures point at the database; auth-route 5xx point at the app. Correlate by requestId in /ecs/${local.name}."

  dimensions = {
    TargetGroup  = aws_lb_target_group.identity.arn_suffix
    LoadBalancer = data.aws_lb.shared.arn_suffix
  }

  treat_missing_data = "notBreaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "target_response_time" {
  alarm_name          = "${local.alarm_prefix}-latency-high"
  actions_enabled     = var.alarm_actions_enabled
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  extended_statistic  = "p95"
  threshold           = var.alb_latency_p95_threshold_seconds
  alarm_description   = "Identity p95 target response time above ${var.alb_latency_p95_threshold_seconds}s for 15 minutes. Every app's login and token refresh sits behind this."

  dimensions = {
    TargetGroup  = aws_lb_target_group.identity.arn_suffix
    LoadBalancer = data.aws_lb.shared.arn_suffix
  }

  treat_missing_data = "notBreaching"

  alarm_actions = [data.aws_sns_topic.alerts.arn]
  ok_actions    = [data.aws_sns_topic.alerts.arn]
}

# ---------------------------------------------------------------------------
# Outputs — so `terraform output` can be diffed against
# `aws cloudwatch describe-alarms --alarm-name-prefix hollis-prod-identity`
# ---------------------------------------------------------------------------

output "alarm_names" {
  description = "Identity CloudWatch alarm names. All must begin with hollis-prod- or the SNS topic and KMS key policies silently drop their notifications."
  value = [
    aws_cloudwatch_metric_alarm.no_healthy_hosts.alarm_name,
    aws_cloudwatch_metric_alarm.task_count_low.alarm_name,
    aws_cloudwatch_metric_alarm.cpu_high.alarm_name,
    aws_cloudwatch_metric_alarm.memory_high.alarm_name,
    aws_cloudwatch_metric_alarm.target_5xx.alarm_name,
    aws_cloudwatch_metric_alarm.target_response_time.alarm_name,
  ]
}

output "alerts_sns_topic_arn" {
  description = "SNS topic the Identity alarms publish to (created and owned by hollis-health-app)."
  value       = data.aws_sns_topic.alerts.arn
}
