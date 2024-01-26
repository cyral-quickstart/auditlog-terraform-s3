# Cyral Configuration
variable "control_plane_host" {
  type        = string
  description = "The host for the Cyral Control Plane API, e.g. tenant.cyral.com."
}

variable "secret_arn" {
  type        = string
  description = <<EOF
    ARN of the entry in AWS Secrets Manager that stores the secret containing
    the credentials for the Cyral API. Either this OR the `client_id` and
    `client_secret` variables are REQUIRED. If empty, the
    `client_id` and `client_secret` variables MUST both be
    provided, and a new secret will be created in AWS Secrets Manager.
  EOF
  default     = ""
}

variable "cyral_secret_arn" {
  type        = string
  description = <<EOF
    ARN of the entry in AWS Secrets Manager that stores the secret containing
    the credentials for the Cyral API. Either this OR the `cyral_client_id` and
    `cyral_client_secret` variables are REQUIRED. If empty, the
    `cyral_client_id` and `cyral_client_secret` variables MUST both be
    provided, and a new secret will be created in AWS Secrets Manager.
  EOF
  default     = ""
}

variable "client_id" {
  type        = string
  description = <<EOF
    The client ID to connect to the Cyral API. This is REQUIRED if the
    `secret_arn` variable is empty.
  EOF
  default     = ""
}

variable "client_secret" {
  type        = string
  description = <<EOF
    The client secret to connect to the Cyral API. This is REQUIRED if the
    `secret_arn` variable is empty.
  EOF
  default     = ""
  sensitive   = true
}

variable "schedule_expression" {
  type        = string
  description = <<EOF
    Schedule expression to invoke the repo crawler. The default value
    represents a run schedule of every six hours.
  EOF
  default     = "cron(0 0 ? * 1 *)"
  validation {
    condition     = can(regex("^cron\\(([^ ]+ ){5}[^ ]+\\)|rate\\([^ ]+ [^ ]+\\)$", var.schedule_expression))
    error_message = "Expression must be either cron(...) or rate(...). See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html."
  }
}

variable "file_name_format" {
  type          = string
  description = <<EOF
    This is utilized to define the file name format, allowing for date injection {START} and {END}.
    You can also control the date format, for example {START:%Y-%m-%d}.
  EOF
  default = "cyral_audit_log_{start:%Y-%m-%dT%H-%M-%S}_to_{end:%Y-%m-%dT%H-%M-%S}.log"
}

variable "audit_log_bucket" {
    type = string
    description = "the name of the bucket to store the audit logs in. The bucket MUST already exist."
}

variable "audit_log_path" {
    type = string
    description = "the path to store the files at. just like with the file_name_format you can utilize {START} and {END} with format control."
    default = ""
  
}

variable "state_file_bucket" {
    type = string
    description = "Bucket to store state file in. Defaults to the audit log bucket"
    default = ""
}

variable "state_file_path" {
    type = string
    description = "The path to store the state file this lambda job."
    default = "audit_pull.state"
}

variable "function_name" {
    type = string
    description = "Name of the lambda function"
    default = "cyral-audit-log-shipper"
}

variable "timeout" {
  type = number
  description = "timeout value for lambda function"
  default = 60
}

variable "lambda_execution_role" {
  type = string
  description = "Provide the role if you have a specific role you'd like to use or leave blank for it to be created"
  default = ""
}