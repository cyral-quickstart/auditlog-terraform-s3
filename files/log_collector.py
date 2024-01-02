''' Cyral Audit Log Pull'''
from datetime import datetime
from urllib.parse import urlencode
import os
import json
import urllib3
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, EndpointConnectionError


def handler(event, context):
    '''entry point for lambda'''

    default_fn_format = 'cyral_audit_log_{start:%Y-%m-%dT%H-%M-%S}_to_{end:%Y-%m-%dT%H-%M-%S}.log'

    # required env vars
    cyral_creds_secret_arn = os.environ.get("CYRAL_CREDS_SECRET_ARN")
    cyral_control_plane = os.environ.get("CYRAL_CONTROL_PLANE")
    audit_log_bucket = os.environ.get("AUDIT_LOG_BUCKET")

    # optional vars
    audit_log_path = os.environ.get("AUDIT_LOG_PATH", '')
    state_file_path = os.environ.get("STATE_FILE_PATH", 'audit_pull.state')
    state_file_bucket = os.environ.get("STATE_FILE_BUCKET") or audit_log_bucket
    file_name_format = os.environ.get("FILE_NAME_FORMAT", default_fn_format)

    # setup
    end_date = datetime.utcnow()
    start_date = get_state_date(state_file_bucket, state_file_path)

    try:
        formatted_filename = file_name_format.format(start=start_date, end=end_date)
    except KeyError:
        print("Incorrect file format. Supports 'start' and 'end' only.")
        return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': "Invalid file name format. Supports only 'start' and 'end'"
                    })
            }
    log_file_path = os.path.join(audit_log_path, formatted_filename)

    # Get cyral Token
    try:
        cyral_creds = get_secret_value(cyral_creds_secret_arn)

        client_id = cyral_creds.get('client-id')
        client_secret = cyral_creds.get('client-secret')

        if client_id is not None and client_secret is not None:
            token = get_cyral_token(cyral_control_plane, client_id, client_secret)
            if not token:
                print("Failed to get token, see previous errors")
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': "Unable to get Token"})
                }
        else:
            print("Client ID or client secret not found in the credentials.")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Client ID or client secret not found'})
            }

    except Exception as e:
        print(f"Failed to obtain Cyral token: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Failed to obtain Cyral token: {e}'})
        }
    # pull log and write to S3
    try:
        log_data = get_cyral_audit_log(control_plane=cyral_control_plane, client_token=token,
                                       start_date=start_date, end_date=end_date)

    except Exception as e:
        print(f"Failed to retrieve audit log: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'{e}'})
        }

    result = write_to_s3(audit_log_bucket, log_file_path, log_data)
    if not result:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Failed to write to S3! check logs'})
         }

    # update state
    result = write_to_s3(state_file_bucket, state_file_path,
                         end_date.strftime('%Y-%m-%dT%H:%M:%SZ'))

    return {'statusCode': 200, 'body': "Successful run"}


def get_state_date(bucket, object_key):
    '''Get the last run date'''
    s3 = boto3.client('s3')

    try:
        response = s3.get_object(Bucket=bucket, Key=object_key)
        state_timestamp = response['Body'].read().decode('utf-8')
        return datetime.strptime(state_timestamp, '%Y-%m-%dT%H:%M:%SZ')

    except Exception:
        print("unable to retrieve start time from state, using default for full range")
        return datetime.strptime('2015-01-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ')


def write_to_s3(bucket, object_key, data):
    '''write log data or state data to S3'''
    s3 = boto3.client('s3')
    print(f"bucket: {bucket} key: {object_key}")
    try:
        s3.put_object(Bucket=bucket, Key=object_key, Body=data)
        return True
    except (NoCredentialsError, PartialCredentialsError,
            EndpointConnectionError) as e:
        print(f"An error occurred: {e}")
        return False

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def get_secret_value(secret_arn):
    '''Read AWS Secret by ARN'''
    client = boto3.client('secretsmanager')

    try:
        response = client.get_secret_value(SecretId=secret_arn)
        secret_value = response['SecretString']

        secret_object = json.loads(secret_value)

        return secret_object
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        exit(1)


def get_cyral_token(control_plane, client_id, client_secret):
    '''Get an access token from the cyral controlplane'''
    token_url = f"https://{control_plane}/v1/users/oidc/token"
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    token_body = urlencode(token_data)

    http = urllib3.PoolManager()

    try:
        response = http.request('POST', token_url, body=token_body,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                retries=False)
        if response.status == 200:
            access_token = json.loads(response.data.decode('utf-8')).get('access_token')
            return access_token
        else:
            print(f"Failed to retrieve token! status code: {response.status} message: {response.data}")
    except Exception as e:
        print(f"An error occured while getting a token from {control_plane}: {e}")
    return None


def get_cyral_audit_log(control_plane, client_token, start_date, end_date):
    '''pull logs cyral controlplane'''
    url = f"https://{control_plane}/v1/auditlog/query"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {client_token}"
    }

    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')

    filter_string = json.dumps({
        "timestamp": {
            "$gte": {"$date": start_date_str},
            "$lte": {"$date": end_date_str}
        }
    })

    query_data = json.dumps({
        "pageSize": 2000,
        "filter": filter_string
    })

    http = urllib3.PoolManager()

    try:
        response = http.request("POST", url, body=query_data, headers=headers)
        if response.status == 200:
            return json.dumps(json.loads(response.data.decode('utf-8'))['logs'])
        else:
            print(f"Error: {response.status}, {response.data}")
            exit(2)
    except Exception as e:
        print(f"An error occured pulling log data: {e}")

    return None
