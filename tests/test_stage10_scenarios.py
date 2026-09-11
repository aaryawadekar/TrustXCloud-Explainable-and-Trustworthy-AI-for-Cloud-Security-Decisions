"""
Test script to check analyzer predictions on all 5 scenarios.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.predict_and_explain import CloudSecurityAnalyzer

analyzer = CloudSecurityAnalyzer()

# Test 1: True Benign (e.g. GetCallerIdentity or DescribeInstances)
benign_event = {
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/devops_admin",
        "userName": "devops_admin",
        "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
    },
    "eventTime": "2026-04-10T14:30:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "DescribeInstances",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "10.100.4.12",
    "userAgent": "aws-cli/2.11.0 Python/3.11.2",
    "errorCode": None,
    "requestParameters": {},
    "is_new_ip_for_identity": 0,
    "is_new_region_for_identity": 0,
    "call_frequency_10m": 2,
}

res1 = analyzer.analyze_event(benign_event)
print(f"Test 1 (Benign): Decision={res1['decision']}, Conf={res1['confidence']:.2%}, XGB={res1['xgboost_probability']:.2%}, Tab={res1['tabnet_probability']:.2%}")

# Test 2: Privilege Escalation (AttachUserPolicy targeting admin user, off-hours, new IP, Kali user-agent)
priv_esc_event = {
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/compromised_dev",
        "userName": "compromised_dev",
        "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
    },
    "eventTime": "2026-04-12T02:45:10Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy",
    "awsRegion": "ap-southeast-1",
    "sourceIPAddress": "198.51.100.24",
    "userAgent": "Kali-Linux-CloudSploit",
    "errorCode": "AccessDenied",
    "requestParameters": {"userName": "target_admin_user"},
    "is_new_ip_for_identity": 1,
    "is_new_region_for_identity": 1,
    "call_frequency_10m": 42,
}

res2 = analyzer.analyze_event(priv_esc_event)
print(f"Test 2 (Priv Esc): Decision={res2['decision']}, Conf={res2['confidence']:.2%}, XGB={res2['xgboost_probability']:.2%}, Tab={res2['tabnet_probability']:.2%}")

# Test 3: Anomalous Event (CreateAccessKey, off-hours burst, foreign region)
anom_event = {
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/bob_contractor",
        "userName": "bob_contractor",
        "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
    },
    "eventTime": "2026-04-14T03:15:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "eu-west-1",
    "sourceIPAddress": "203.0.113.88",
    "userAgent": "botocore/1.29.0 raw-script",
    "errorCode": None,
    "requestParameters": {"userName": "carol_secops"},
    "is_new_ip_for_identity": 1,
    "is_new_region_for_identity": 1,
    "call_frequency_10m": 28,
}

res3 = analyzer.analyze_event(anom_event)
print(f"Test 3 (Anomalous): Decision={res3['decision']}, Conf={res3['confidence']:.2%}, XGB={res3['xgboost_probability']:.2%}, Tab={res3['tabnet_probability']:.2%}")

# Test 4: False-Positive-Like Event (AssumeRole, business hours, known IP, MFA on)
fp_event = {
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/carol_secops",
        "userName": "carol_secops",
        "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
    },
    "eventTime": "2026-04-15T10:30:00Z",
    "eventSource": "sts.amazonaws.com",
    "eventName": "AssumeRole",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "10.100.4.55",
    "userAgent": "aws-cli/2.11.0 Python/3.11.2",
    "errorCode": None,
    "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/ReadOnlyAuditRole"},
    "is_new_ip_for_identity": 0,
    "is_new_region_for_identity": 0,
    "call_frequency_10m": 2,
}

res4 = analyzer.analyze_event(fp_event)
print(f"Test 4 (FP-like): Decision={res4['decision']}, Conf={res4['confidence']:.2%}, XGB={res4['xgboost_probability']:.2%}, Tab={res4['tabnet_probability']:.2%}")

# Test 5: Malformed event
malformed_event = {}
res5 = analyzer.analyze_event(malformed_event)
print(f"Test 5 (Malformed): Decision={res5['decision']}, ErrorMsg={res5.get('error_message')}")

print("\nALL 5 SCENARIOS EXECUTED SUCCESSFULLY.")
