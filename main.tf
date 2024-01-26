resource "random_id" "this" {
  byte_length = 8
}

locals {
  secret_arn          = var.secret_arn != "" ? var.secret_arn : aws_secretsmanager_secret.secret[0].arn
  create_lambda_role  = var.lambda_execution_role == "" 
}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "execution_policy" {
  # Allows access to the necessary secrets in Secrets Manager.
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = [
      local.secret_arn
    ]
  }

  # Allows access to write CloudWatch logs.
  statement {
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:CreateLogGroup",
      "logs:DescribeLogStreams",
    ]
    effect    = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
    ]
  }

   dynamic "statement" {
    for_each = var.state_file_bucket != "" ? [1] : []
    content {
      actions = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
      ]
      effect    = "Allow"
      resources = [
        "arn:aws:s3:::${var.state_file_bucket}/*",
        "arn:aws:s3:::${var.state_file_bucket}",
      ]
    }
  }

  # Always include S3 permissions for audit_log_bucket
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    effect    = "Allow"
    resources = [
      "arn:aws:s3:::${var.audit_log_bucket}/*",
      "arn:aws:s3:::${var.audit_log_bucket}",
    ]
  }
}

resource "aws_iam_role" "this" {
  count              = local.create_lambda_role ? 1 : 0
  name               = "${var.function_name}-execution-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  inline_policy {
    name   = "${var.function_name}-execution-policy"
    policy = data.aws_iam_policy_document.execution_policy.json
  }
}

resource "aws_cloudwatch_event_rule" "this" {
  name                = "${var.function_name}-event-rule"
  description         = "Runs the cyral audit log shipper function as specified by the scheduled expression."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "this" {
    rule  = aws_cloudwatch_event_rule.this.name
    arn   = aws_lambda_function.this.arn
}

resource "aws_secretsmanager_secret" "secret" {
  count       = var.secret_arn != "" ? 0 : 1
  name        = "/${var.function_name}/CyralSecret"
  description = "Cyral API credentials (client ID and secret) for audit log shipper lambda"
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  count         = var.secret_arn != "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.secret[0].id
  secret_string = jsonencode(
    {
      client-id     = var.client_id,
      client-secret = var.client_secret,
    }
  )
}

data "archive_file" "lambda_script" {
  type        = "zip"
  source_file  = "${path.module}/files/log_collector.py"
  output_path = "${path.module}/files/log-collector.zip"
}


resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = local.create_lambda_role ? aws_iam_role.this[0].arn : var.lambda_execution_role
  timeout       = var.timeout
  runtime       = "python3.10"
  filename         = data.archive_file.lambda_script.output_path
  source_code_hash = data.archive_file.lambda_script.output_base64sha256
  handler       = "log_collector.handler"


  environment {
    variables = {
      CYRAL_CREDS_SECRET_ARN    = local.secret_arn
      CYRAL_CONTROL_PLANE       = var.control_plane_host
      AUDIT_LOG_BUCKET          = var.audit_log_bucket
      AUDIT_LOG_PATH            = var.audit_log_path
      STATE_FILE_PATH           = var.state_file_path
      STATE_FILE_BUCKET         = var.state_file_bucket
      FILE_NAME_FORMAT          = var.file_name_format
    }
  }
  depends_on = [ aws_iam_role.this ]
}

resource "aws_lambda_permission" "this" {
  function_name = aws_lambda_function.this.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}