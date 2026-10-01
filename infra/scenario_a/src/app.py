import json

def lambda_handler(event, context):
    # We do NOT import requests here on purpose.
    # requests==2.19.0 is very old and may crash on Python 3.11.
    # LambdaGuard only needs the package to be present and listed.
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "hello from scenario A"}),
    }