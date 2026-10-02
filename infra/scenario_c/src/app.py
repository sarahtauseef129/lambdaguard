import os

def lambda_handler(event, context):
    # Env vars tell discovery which resources this function is connected to.
    return {
        "bucket": os.environ.get("BUCKET_NAME"),
        "table": os.environ.get("TABLE_NAME"),
        "message": "scenario C nightly job ran",
    }