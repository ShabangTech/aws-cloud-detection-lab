# Response: EventBridge sees AuthorizeSecurityGroupIngress in CloudTrail and
# invokes a Python Lambda that closes SSH/RDP rules open to the internet.
# Detection D05 still fires, so the analyst gets both the alert and the fix.

data "archive_file" "sg_remediator" {
  type        = "zip"
  source_file = "${path.module}/lambda/sg_remediator.py"
  output_path = "${path.module}/build/sg_remediator.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sg_remediator" {
  count = var.enable_auto_remediation ? 1 : 0

  name               = "${var.name_prefix}-sg-remediator"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege: read security groups, revoke ingress, publish one topic,
# write its own logs. Nothing else.
data "aws_iam_policy_document" "sg_remediator" {
  #checkov:skip=CKV_AWS_356:ec2:DescribeSecurityGroups does not support resource-level permissions
  #checkov:skip=CKV_AWS_111:Revoke must work on any security group the attacker opens; scoped to this account and region

  statement {
    sid       = "ReadSecurityGroups"
    actions   = ["ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  statement {
    sid       = "RevokeIngress"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:security-group/*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-sg-remediator:*"]
  }
}

resource "aws_iam_role_policy" "sg_remediator" {
  count = var.enable_auto_remediation ? 1 : 0

  name   = "sg-remediator"
  role   = aws_iam_role.sg_remediator[0].id
  policy = data.aws_iam_policy_document.sg_remediator.json
}

resource "aws_cloudwatch_log_group" "sg_remediator" {
  #checkov:skip=CKV_AWS_338:Lab keeps function logs 30 days
  #checkov:skip=CKV_AWS_158:Function logs hold only security group IDs; a customer KMS key would add a monthly charge
  count = var.enable_auto_remediation ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-sg-remediator"
  retention_in_days = 30
}

resource "aws_lambda_function" "sg_remediator" {
  #checkov:skip=CKV_AWS_117:Calls only AWS APIs; placing it in a VPC would need NAT or endpoints (paid)
  #checkov:skip=CKV_AWS_116:EventBridge retries failed invocations; a DLQ is out of scope for the lab
  #checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with a low concurrency quota
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for a single-author lab
  #checkov:skip=CKV_AWS_173:The only environment variable is a topic ARN, which is not secret
  #checkov:skip=CKV_AWS_50:X-Ray tracing is not needed for a single short function
  count = var.enable_auto_remediation ? 1 : 0

  function_name    = "${var.name_prefix}-sg-remediator"
  description      = "Closes security group rules that open SSH or RDP to the internet"
  role             = aws_iam_role.sg_remediator[0].arn
  runtime          = "python3.13"
  handler          = "sg_remediator.handler"
  filename         = data.archive_file.sg_remediator.output_path
  source_code_hash = data.archive_file.sg_remediator.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.sg_remediator, aws_iam_role_policy.sg_remediator]
}

resource "aws_cloudwatch_event_rule" "sg_ingress" {
  count = var.enable_auto_remediation ? 1 : 0

  name        = "${var.name_prefix}-sg-ingress-opened"
  description = "CloudTrail: a security group ingress rule was added"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_ingress" {
  count = var.enable_auto_remediation ? 1 : 0

  rule = aws_cloudwatch_event_rule.sg_ingress[0].name
  arn  = aws_lambda_function.sg_remediator[0].arn
}

resource "aws_lambda_permission" "eventbridge" {
  count = var.enable_auto_remediation ? 1 : 0

  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_remediator[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_ingress[0].arn
}
