"""
Test script to verify AWS ingestion (S3 parser) and storage (DynamoDB store).
"""
import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws.s3_cloudtrail_parser import S3CloudTrailParser
from aws.dynamodb_store import DynamoDBSecurityStore
from src.predict_and_explain import CloudSecurityAnalyzer

def test_s3_parser():
    print("=" * 60)
    print("TESTING S3 CLOUDTRAIL PARSER")
    print("=" * 60)
    parser = S3CloudTrailParser(bucket_name="test-cloudtrail-bucket")
    # Verify offline / simulation fallback
    parser.process_s3_object("AWSLogs/test/cloudtrail.json.gz")
    print("[+] S3 Parser test completed successfully.\n")

def test_dynamodb_store():
    print("=" * 60)
    print("TESTING DYNAMODB SECURITY STORE")
    print("=" * 60)
    store = DynamoDBSecurityStore()
    store.create_table_if_not_exists()
    
    analyzer = CloudSecurityAnalyzer()
    
    # Run a test event through analyzer and store result
    test_event = {
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/attacker",
            "userName": "attacker",
            "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
        },
        "eventTime": "2026-04-12T02:45:10Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "ap-southeast-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "Kali-Linux-CloudSploit",
        "errorCode": "AccessDenied",
        "requestParameters": {"userName": "admin"},
        "is_new_ip_for_identity": 1,
        "is_new_region_for_identity": 1,
        "call_frequency_10m": 50,
    }
    
    res = analyzer.analyze_event(test_event)
    record_id = store.put_decision_record(res)
    
    assert len(store.mock_store) > 0, "No records stored in mock store"
    saved = store.mock_store[-1]
    assert saved["decision_id"] == record_id
    assert saved["decision"] == "THREAT"
    assert saved["model_version"] == "v3.0"
    assert "xgboost_probability" in saved
    assert "tabnet_probability" in saved
    assert "llm_faithful" in saved
    
    print(f"[+] Successfully stored and verified V3 decision record: {record_id}")
    print(f"    Decision: {saved['decision']}")
    print(f"    Model Version: {saved['model_version']}")
    print(f"    XGBoost Prob: {saved['xgboost_probability']}")
    print(f"    TabNet Prob: {saved['tabnet_probability']}")
    print(f"    LLM Faithful: {saved['llm_faithful']}")
    print("[+] DynamoDB Store test completed successfully.\n")

if __name__ == "__main__":
    test_s3_parser()
    test_dynamodb_store()
    print("ALL AWS INTEGRATION TESTS PASSED.")
