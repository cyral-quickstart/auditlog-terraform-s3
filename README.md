# Audit Logs - Lambda Pull to S3

This will deploy a Lambda that will run on a  cron schedule to pull Cyral Control Plan audit logs and push them to S3.

## Requirements

### API key

You'll have to create a client ID and secret on the control plane to allow the lambda to retrieve the audit logs. The API key will need `View Audit Logs` permissions.

### S3 Bucket

This terraform will not create the bucket for you, it expects the bucket to already exist.

## Quick Setup

```terraform
client_id = ""
client_secret = ""
control_plane_host = ""
audit_log_bucket = ""
```

## Advanced Configuration

There are several other variables that will allow you to have more control over how this works. Please review [variables.tf](variables.tf) to see all options.
