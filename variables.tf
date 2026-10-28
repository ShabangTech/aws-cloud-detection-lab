variable "region" {
  description = "AWS region. Must match the landing zone's home region."
  type        = string
  default     = "us-east-2"
}

variable "name_prefix" {
  description = "Short prefix used in resource names."
  type        = string
  default     = "cdl"
}

variable "owner" {
  description = "Owner tag applied to every resource."
  type        = string
  default     = "shabangtech"
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch log group that receives CloudTrail (landing zone output cloudtrail_log_group_name)."
  type        = string
  default     = "/hlz/cloudtrail"
}

variable "alert_email" {
  description = "Email address that receives detection alerts. AWS sends a confirmation link first."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "enable_auto_remediation" {
  description = "Deploy the Lambda that automatically closes security group rules opening SSH or RDP to the internet."
  type        = bool
  default     = true
}

variable "metric_namespace" {
  description = "CloudWatch namespace for detection metrics."
  type        = string
  default     = "DetectionLab"
}
