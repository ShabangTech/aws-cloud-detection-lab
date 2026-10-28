# Detections: each one is a CloudWatch Logs metric filter on the CloudTrail
# log group plus an alarm that emails the SOC topic. Every detection maps to
# a MITRE ATT&CK technique. Details, false positives and test steps for each
# one are in docs/DETECTIONS.md.
#
# Nine detections = nine custom metrics and nine alarms, inside the
# CloudWatch free tier (10 of each).

locals {
  # scope = "regional": fires on any account, including AWS "projects" accounts.
  # scope = "global":   IAM events. CloudTrail delivers these only to a
  #                     multi-Region trail (or a trail in us-east-1), so on a
  #                     projects account they stay silent. See docs/DETECTIONS.md.
  detections = {
    D01-logging-tampering = {
      title     = "Logging or detection tampering"
      severity  = "CRITICAL"
      mitre     = "T1562.008 Impair Defenses: Disable or Modify Cloud Logs"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail) || ($.eventName = PutEventSelectors) || ($.eventName = DeleteFlowLogs) || ($.eventName = DeleteLogGroup) || ($.eventName = DeleteMetricFilter) || ($.eventName = DeleteAlarms) || ($.eventName = DisableAlarmActions) }"
    }

    D02-sg-open-to-world = {
      title     = "Security group opened to the internet"
      severity  = "HIGH"
      mitre     = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ($.eventName = AuthorizeSecurityGroupIngress) && (($.requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp = \"0.0.0.0/0\") || ($.requestParameters.ipPermissions.items[0].ipv6Ranges.items[0].cidrIpv6 = \"::/0\")) }"
    }

    D03-s3-exposure-controls = {
      title     = "S3 bucket policy, ACL or public access block changed"
      severity  = "HIGH"
      mitre     = "T1530 Data from Cloud Storage (exposure precursor)"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy) || ($.eventName = PutBucketAcl) || ($.eventName = DeleteBucketPublicAccessBlock) || ($.eventName = PutBucketPublicAccessBlock) || ($.eventName = DeleteAccountPublicAccessBlock) }"
    }

    D04-kms-key-destruction = {
      title     = "KMS key disabled or scheduled for deletion"
      severity  = "HIGH"
      mitre     = "T1485 Data Destruction"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }

    D05-access-denied-burst = {
      title     = "Burst of denied API calls (5+ in 5 minutes)"
      severity  = "MEDIUM"
      mitre     = "T1580 Cloud Infrastructure Discovery"
      scope     = "regional"
      threshold = 5
      pattern   = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }

    D06-ssh-key-added = {
      title     = "EC2 SSH key pair created or imported"
      severity  = "MEDIUM"
      mitre     = "T1098.004 Account Manipulation: SSH Authorized Keys"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ($.eventName = CreateKeyPair) || ($.eventName = ImportKeyPair) }"
    }

    D07-secrets-read = {
      title     = "Secret values read (SSM SecureString or Secrets Manager)"
      severity  = "MEDIUM"
      mitre     = "T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores"
      scope     = "regional"
      threshold = 1
      pattern   = "{ ((($.eventName = GetParameter) || ($.eventName = GetParameters)) && ($.requestParameters.withDecryption IS TRUE)) || ($.eventName = GetSecretValue) }"
    }

    D08-iam-credential-persistence = {
      title     = "New IAM user, console password or access key"
      severity  = "HIGH"
      mitre     = "T1098.001 Additional Cloud Credentials / T1136.003 Create Cloud Account"
      scope     = "global"
      threshold = 1
      pattern   = "{ ($.eventName = CreateUser) || ($.eventName = CreateLoginProfile) || ($.eventName = CreateAccessKey) }"
    }

    D09-admin-granted = {
      title     = "Administrator access granted"
      severity  = "CRITICAL"
      mitre     = "T1098.003 Account Manipulation: Additional Cloud Roles"
      scope     = "global"
      threshold = 1
      pattern   = "{ (($.eventName = AttachUserPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = AttachGroupPolicy)) && ($.requestParameters.policyArn = \"arn:aws:iam::aws:policy/AdministratorAccess\") }"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = "${var.name_prefix}-${each.key}"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name        = "${var.name_prefix}-${each.key}"
  alarm_description = "[${each.value.severity}] ${each.value.title}. MITRE ATT&CK ${each.value.mitre}. Triage: run the '${var.name_prefix}/triage-recent-activity' Logs Insights query."

  namespace           = var.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}
