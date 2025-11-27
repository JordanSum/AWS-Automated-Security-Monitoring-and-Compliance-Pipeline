import boto3
import json
from datetime import datetime, timedelta
from typing import List, Dict

class IAMSecurityAuditor:
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.findings = []
    
    def audit_password_policy(self) -> Dict:
        """Check if password policy meets CIS benchmarks"""
        try:
            policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            
            issues = []
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append("Password length < 14 characters")
            if not policy.get('RequireSymbols', False):
                issues.append("Symbols not required")
            if not policy.get('RequireNumbers', False):
                issues.append("Numbers not required")
            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("Uppercase not required")
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append("Lowercase not required")
            if policy.get('MaxPasswordAge', 999) > 90:
                issues.append("Password rotation > 90 days")
            
            return {
                'check': 'Password Policy',
                'status': 'FAIL' if issues else 'PASS',
                'issues': issues,
                'severity': 'HIGH' if issues else 'INFO'
            }
        except self.iam_client.exceptions.NoSuchEntityException:
            return {
                'check': 'Password Policy',
                'status': 'FAIL',
                'issues': ['No password policy configured'],
                'severity': 'CRITICAL'
            }
    
    def audit_root_account(self) -> List[Dict]:
        """Audit root account usage and MFA status"""
        findings = []
        
        # Check root access keys
        try:
            summary = self.iam_client.get_account_summary()
            if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                findings.append({
                    'check': 'Root Access Keys',
                    'status': 'FAIL',
                    'issues': ['Root account has active access keys'],
                    'severity': 'CRITICAL',
                    'remediation': 'Delete root access keys immediately'
                })
        except Exception as e:
            findings.append({
                'check': 'Root Access Keys',
                'status': 'ERROR',
                'issues': [str(e)],
                'severity': 'HIGH'
            })
        
        # Check root MFA
        try:
            mfa_devices = self.iam_client.list_virtual_mfa_devices()
            root_mfa_enabled = any(
                device.get('User', {}).get('Arn', '').endswith(':root')
                for device in mfa_devices['VirtualMFADevices']
            )
            
            if not root_mfa_enabled:
                findings.append({
                    'check': 'Root MFA',
                    'status': 'FAIL',
                    'issues': ['Root account does not have MFA enabled'],
                    'severity': 'CRITICAL',
                    'remediation': 'Enable MFA for root account'
                })
        except Exception as e:
            findings.append({
                'check': 'Root MFA',
                'status': 'ERROR',
                'issues': [str(e)],
                'severity': 'HIGH'
            })
        
        return findings
    
    def audit_unused_credentials(self, days: int = 90) -> List[Dict]:
        """Find IAM users with credentials unused for X days"""
        findings = []
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Check password last used
                    if 'PasswordLastUsed' in user:
                        if user['PasswordLastUsed'] < cutoff_date:
                            findings.append({
                                'check': 'Unused Credentials',
                                'status': 'FAIL',
                                'issues': [f"User {username} password unused for {days}+ days"],
                                'severity': 'MEDIUM',
                                'resource': username,
                                'remediation': f'Disable or delete user {username}'
                            })
                    
                    # Check access keys
                    access_keys = self.iam_client.list_access_keys(UserName=username)
                    for key in access_keys['AccessKeyMetadata']:
                        key_id = key['AccessKeyId']
                        key_last_used = self.iam_client.get_access_key_last_used(
                            AccessKeyId=key_id
                        )
                        
                        if 'LastUsedDate' in key_last_used['AccessKeyLastUsed']:
                            last_used = key_last_used['AccessKeyLastUsed']['LastUsedDate']
                            if last_used.replace(tzinfo=None) < cutoff_date:
                                findings.append({
                                    'check': 'Unused Access Keys',
                                    'status': 'FAIL',
                                    'issues': [f"Access key {key_id} for {username} unused for {days}+ days"],
                                    'severity': 'MEDIUM',
                                    'resource': f"{username}/{key_id}",
                                    'remediation': f'Deactivate or delete access key {key_id}'
                                })
        
        except Exception as e:
            findings.append({
                'check': 'Unused Credentials',
                'status': 'ERROR',
                'issues': [str(e)],
                'severity': 'HIGH'
            })
        
        return findings
    
    def audit_overly_permissive_policies(self) -> List[Dict]:
        """Find policies with overly broad permissions"""
        findings = []
        dangerous_actions = ['*', 's3:*', 'iam:*', 'ec2:*']
        
        try:
            # Check customer-managed policies
            paginator = self.iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['Arn']
                    
                    # Get default policy version
                    version = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_document = version['PolicyVersion']['Document']
                    
                    # Check for wildcard actions
                    for statement in policy_document.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                if action in dangerous_actions:
                                    findings.append({
                                        'check': 'Overly Permissive Policies',
                                        'status': 'FAIL',
                                        'issues': [f"Policy {policy_name} contains wildcard action: {action}"],
                                        'severity': 'HIGH',
                                        'resource': policy_arn,
                                        'remediation': 'Replace wildcard with specific actions'
                                    })
                            
                            # Check for Resource: "*" with broad actions
                            resources = statement.get('Resource', [])
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            if '*' in resources and len(actions) > 10:
                                findings.append({
                                    'check': 'Overly Permissive Policies',
                                    'status': 'FAIL',
                                    'issues': [f"Policy {policy_name} allows many actions on all resources"],
                                    'severity': 'HIGH',
                                    'resource': policy_arn,
                                    'remediation': 'Restrict Resource to specific ARNs'
                                })
        
        except Exception as e:
            findings.append({
                'check': 'Overly Permissive Policies',
                'status': 'ERROR',
                'issues': [str(e)],
                'severity': 'HIGH'
            })
        
        return findings
    
    def generate_report(self) -> str:
        """Run all audits and generate report"""
        print("🔍 Starting IAM Security Audit...\n")
        
        all_findings = []
        
        # Run all audits
        all_findings.append(self.audit_password_policy())
        all_findings.extend(self.audit_root_account())
        all_findings.extend(self.audit_unused_credentials(90))
        all_findings.extend(self.audit_overly_permissive_policies())
        
        # Generate report
        report = {
            'audit_date': datetime.now().isoformat(),
            'total_checks': len(all_findings),
            'critical': sum(1 for f in all_findings if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in all_findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in all_findings if f.get('severity') == 'MEDIUM'),
            'findings': all_findings
        }
        
        # Print summary
        print("=" * 60)
        print("IAM SECURITY AUDIT REPORT")
        print("=" * 60)
        print(f"Total Checks: {report['total_checks']}")
        print(f"🔴 Critical: {report['critical']}")
        print(f"🟠 High: {report['high']}")
        print(f"🟡 Medium: {report['medium']}")
        print("=" * 60)
        print()
        
        # Print findings
        for finding in all_findings:
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'INFO': '🟢'
            }
            
            print(f"{severity_emoji.get(finding['severity'], '⚪')} {finding['check']}: {finding['status']}")
            for issue in finding.get('issues', []):
                print(f"   └─ {issue}")
            if 'remediation' in finding:
                print(f"   💡 Remediation: {finding['remediation']}")
            print()
        
        # Save to file
        output_dir = 'Reports'
        filename = f'iam_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        output_path = f'{output_dir}/{filename}'
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Report saved to: {output_path}\n")
        
        return json.dumps(report, indent=2, default=str)


if __name__ == '__main__':
    auditor = IAMSecurityAuditor()
    auditor.generate_report()