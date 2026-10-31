# Threat hunting: saved CloudWatch Logs Insights queries an analyst runs
# after an alert fires. Saved queries are free; you pay only for data
# scanned when you run one (fractions of a cent at lab volume).

locals {
  hunting_queries = {
    "triage-recent-activity" = <<-EOQ
      # Who did what in the last hour? Start every investigation here.
      # AWS services (S3, CloudWatch Logs) calling KMS for log encryption are
      # dropped so human actions come first.
      fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, errorCode
      | filter eventName not like /^(Get|List|Describe|Lookup)/
      | filter userIdentity.type != "AWSService"
      | sort @timestamp desc
      | limit 100
    EOQ

    "denied-calls-by-identity" = <<-EOQ
      # Recon often shows up as many AccessDenied errors from one identity.
      fields userIdentity.arn, eventName, errorCode
      | filter ispresent(errorCode)
      | stats count(*) as denied by userIdentity.arn, eventName, errorCode
      | sort denied desc
    EOQ

    "new-credentials-and-users" = <<-EOQ
      # Persistence: new users, roles, passwords, access keys and admin grants.
      # IAM events are global: this only returns rows with a multi-Region trail.
      fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, requestParameters.policyArn
      | filter eventName in ["CreateUser", "CreateRole", "CreateLoginProfile", "CreateAccessKey", "CreatePolicy", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"]
      | sort @timestamp desc
    EOQ

    "defense-evasion" = <<-EOQ
      # Anyone touching logging, alarms, firewalls or encryption keys.
      fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
      | filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs", "DeleteLogGroup", "DeleteAlarms", "DisableKey", "ScheduleKeyDeletion", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]
      | sort @timestamp desc
    EOQ

    "activity-by-source-ip" = <<-EOQ
      # Which IP addresses are calling the account, and how often?
      stats count(*) as calls by sourceIPAddress, userIdentity.arn
      | sort calls desc
    EOQ
  }
}

resource "aws_cloudwatch_query_definition" "hunt" {
  for_each = local.hunting_queries

  name            = "${var.name_prefix}/${each.key}"
  log_group_names = [var.cloudtrail_log_group_name]
  query_string    = each.value
}
