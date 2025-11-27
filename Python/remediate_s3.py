import boto3
import json

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    securityhub = boto3.client('securityhub')
    
    # Get bucket name from Security Hub finding
    bucket_name = event['detail']['findings'][0]['Resources'][0]['Id'].split(':')[-1]
    
    print(f"🔒 Remediating public access for bucket: {bucket_name}")
    
    # Block all public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    # Delete the public bucket policy
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
    except Exception as e:
        print(f"No bucket policy to delete: {e}")
    
    print(f"✅ Successfully remediated bucket: {bucket_name}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'Remediated bucket: {bucket_name}')
    }