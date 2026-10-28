output "alert_topic_arn" {
  description = "SNS topic every detection and auto-fix publishes to."
  value       = aws_sns_topic.alerts.arn
}

output "detections" {
  description = "Alarm name => MITRE ATT&CK technique (and scope)."
  value       = { for k, d in local.detections : aws_cloudwatch_metric_alarm.detection[k].alarm_name => "${d.mitre} [${d.scope}]" }
}

output "hunting_queries" {
  description = "Saved Logs Insights queries (CloudWatch > Logs Insights > Saved queries)."
  value       = [for q in aws_cloudwatch_query_definition.hunt : q.name]
}

output "auto_remediation_function" {
  description = "Lambda that closes world-open SSH/RDP rules (null when disabled)."
  value       = try(aws_lambda_function.sg_remediator[0].function_name, null)
}

output "next_step" {
  description = "Reminder printed after apply."
  value       = "Check ${var.alert_email} and click 'Confirm subscription' from AWS Notifications, or no alerts will arrive."
}
