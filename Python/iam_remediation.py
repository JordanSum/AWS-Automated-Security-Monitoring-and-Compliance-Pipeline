import boto3
from datetime import datetime

class IAMRemediator:
    def __init__(self, dry_run=True):
        self.iam_client = boto3.client('iam')
        self.dry_run = dry_run
        
    def disable_unused_access_keys(self, days=90):
        """Disable access keys not used in X days"""
        print(f"🔧 Checking for unused access keys (>{days} days)...\n")
        
        users = self.iam_client.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            access_keys = self.iam_client.list_access_keys(UserName=username)
            
            for key in access_keys['AccessKeyMetadata']:
                key_id = key['AccessKeyId']
                
                # Get last used info
                last_used_response = self.iam_client.get_access_key_last_used(
                    AccessKeyId=key_id
                )
                
                if 'LastUsedDate' in last_used_response['AccessKeyLastUsed']:
                    last_used = last_used_response['AccessKeyLastUsed']['LastUsedDate']
                    age = (datetime.now(last_used.tzinfo) - last_used).days
                    
                    if age > days and key['Status'] == 'Active':
                        print(f"⚠️  Key {key_id} for user {username} unused for {age} days")
                        
                        if not self.dry_run:
                            self.iam_client.update_access_key(
                                UserName=username,
                                AccessKeyId=key_id,
                                Status='Inactive'
                            )
                            print(f"   ✅ Disabled key {key_id}")
                        else:
                            print(f"   ℹ️  DRY RUN: Would disable key {key_id}")
                        print()
    
    def enforce_mfa_for_console_users(self):
        """Check which users have console access without MFA"""
        print("🔧 Checking MFA status for console users...\n")
        
        users = self.iam_client.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            
            # Check if user has console access
            try:
                login_profile = self.iam_client.get_login_profile(UserName=username)
                
                # Check MFA devices
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                
                if len(mfa_devices['MFADevices']) == 0:
                    print(f"⚠️  User {username} has console access without MFA")
                    print(f"   ℹ️  Recommendation: Enforce MFA via IAM policy or disable console access")
                    print()
                    
            except self.iam_client.exceptions.NoSuchEntityException:
                # User doesn't have console access
                pass


if __name__ == '__main__':
    # Run in dry-run mode first
    remediator = IAMRemediator(dry_run=True)
    remediator.disable_unused_access_keys(90)
    remediator.enforce_mfa_for_console_users()