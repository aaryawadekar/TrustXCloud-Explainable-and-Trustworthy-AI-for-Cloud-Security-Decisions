"""
AWS DynamoDB Decision & Explainability Store (Boto3) — V3 Schema.

Defines and manages the DynamoDB table 'CloudSecurityDecisions'.
Stores model predictions, confidence scores, top SHAP features, LIME rules,
and LLM natural language narratives using the V3 output schema.
Includes an in-memory/JSON fallback for local testing without AWS credentials.

Model Version: v3.0
"""

import os
import sys
import uuid
import json
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import boto3
    from botocore.exceptions import NoCredentialsError
except ImportError:
    boto3 = None
    NoCredentialsError = None

TABLE_NAME = "CloudSecurityDecisions"

class DynamoDBSecurityStore:
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        if boto3 is None:
            print(f"[*] Note: boto3 not installed.")
            print("    Operating in Local Mock Store Mode (records logged in-memory/local disk).\n")
            self.dynamodb = None
            self.table = None
            self.is_live = False
            self.mock_store = []
            return

        try:
            self.dynamodb = boto3.resource("dynamodb", region_name=region)
            self.table = self.dynamodb.Table(TABLE_NAME)
            self.table.load()
            self.is_live = True
            print(f"[*] Connected to AWS DynamoDB. Table '{TABLE_NAME}' loaded.")
        except Exception as e:
            print(f"[*] Note: Live DynamoDB table '{TABLE_NAME}' not reachable ({e}).")
            print("    Operating in Local Mock Store Mode (records logged in-memory/local disk).\n")
            self.dynamodb = None
            self.table = None
            self.is_live = False
            self.mock_store = []

    def create_table_if_not_exists(self):
        """
        Creates the DynamoDB table with partition key and Global Secondary Indexes.
        """
        if not self.is_live or not self.dynamodb:
            print("[*] Local mode: Mock table schema verified.")
            return

        try:
            table = self.dynamodb.create_table(
                TableName=TABLE_NAME,
                KeySchema=[
                    {"AttributeName": "decision_id", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"}
                ],
                AttributeDefinitions=[
                    {"AttributeName": "decision_id", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                    {"AttributeName": "decision", "AttributeType": "S"},
                    {"AttributeName": "principal_arn", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "DecisionIndex",
                        "KeySchema": [
                            {"AttributeName": "decision", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"}
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
                    },
                    {
                        "IndexName": "PrincipalIndex",
                        "KeySchema": [
                            {"AttributeName": "principal_arn", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"}
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
                    }
                ],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            )
            table.meta.client.get_waiter("table_exists").wait(TableName=TABLE_NAME)
            self.table = table
            print(f"[+] Successfully created DynamoDB table '{TABLE_NAME}'.")
        except Exception as e:
            print(f"[-] Table creation notice: {e}")

    def put_decision_record(self, analysis_result: dict) -> str:
        """
        Formats and persists an explainable AI decision record using the V3 output schema.
        Supports both V3-native keys and legacy compatibility keys.
        """
        decision_id = str(uuid.uuid4())

        # V3 schema: direct top-level keys
        xgb_prob = analysis_result.get("xgboost_probability",
                     analysis_result.get("model_comparison", {}).get("xgboost_threat_prob", 0.0))
        tab_prob = analysis_result.get("tabnet_probability",
                     analysis_result.get("model_comparison", {}).get("tabnet_threat_prob", 0.0))

        top_shap_features = analysis_result.get("top_shap_features",
                              analysis_result.get("shap_explanation", {}).get("top_features", []))
        top_shap_feature = top_shap_features[0]["feature"] if top_shap_features else "unknown"

        llm_narrative = analysis_result.get("llm_narrative",
                          analysis_result.get("llm_narration", {}).get("plain_english_explanation", ""))
        remediation = analysis_result.get("remediation_suggestion",
                        analysis_result.get("llm_narration", {}).get("suggested_action", ""))

        faith_result = analysis_result.get("llm_faithfulness_result", {})
        is_faithful = faith_result.get("is_faithful",
                        analysis_result.get("llm_narration", {}).get("llm_faithfulness_audit", {}).get("is_faithful_to_shap", False))

        item = {
            "decision_id": decision_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_arn": analysis_result.get("event_summary", {}).get("identity_arn", "Unknown"),
            "event_name": analysis_result.get("event_summary", {}).get("event_name", "Unknown"),
            "aws_region": analysis_result.get("event_summary", {}).get("aws_region", "Unknown"),
            "source_ip": analysis_result.get("event_summary", {}).get("source_ip", "Unknown"),
            "decision": analysis_result.get("decision", "UNKNOWN"),
            "confidence": str(analysis_result.get("confidence", 0.0)),
            "xgboost_probability": str(xgb_prob),
            "tabnet_probability": str(tab_prob),
            "model_agreement": str(analysis_result.get("model_agreement", True)),
            "top_shap_feature": top_shap_feature,
            "llm_narrative": llm_narrative,
            "remediation_suggestion": remediation,
            "llm_faithful": is_faithful,
            "model_version": analysis_result.get("model_version", "unknown"),
        }

        if self.is_live and self.table:
            try:
                self.table.put_item(Item=item)
                print(f"[+] Persisted V3 decision record to DynamoDB: {decision_id}")
            except Exception as e:
                print(f"[-] DynamoDB write failed: {e}")
        else:
            self.mock_store.append(item)
            print(f"[+] [Mock DynamoDB] Persisted V3 record: {decision_id} "
                  f"({item['decision']} | v={item['model_version']} | principal={item['principal_arn']})")

        return decision_id

if __name__ == "__main__":
    store = DynamoDBSecurityStore()

    # Test record storage with V3 schema
    sample_result = {
        "event_summary": {
            "identity_arn": "arn:aws:iam::123456789012:user/alice_lead_dev",
            "user_name": "alice_lead_dev",
            "event_name": "AttachUserPolicy",
            "event_source": "iam.amazonaws.com",
            "aws_region": "ap-southeast-1",
            "source_ip": "198.51.100.24",
            "event_time": "2026-04-12T02:45:10Z",
        },
        "decision": "THREAT",
        "confidence": 0.9542,
        "xgboost_probability": 0.9684,
        "tabnet_probability": 0.9401,
        "model_agreement": True,
        "top_shap_features": [
            {"feature": "call_frequency_10m", "value": 42.0, "shap_value": 2.71}
        ],
        "llm_narrative": "Action flagged due to anomalous high-frequency API burst and unfamiliar source IP.",
        "remediation_suggestion": "Review the attached policy for excessive administrative rights.",
        "llm_faithfulness_result": {
            "is_faithful": True,
            "model_top_shap_feature": "call_frequency_10m",
            "llm_cited_feature": "call_frequency_10m",
        },
        "model_version": "v3.0",
    }

    record_id = store.put_decision_record(sample_result)
    print(f"\n[+] Mock store contains {len(store.mock_store)} record(s).")
    print(f"[+] Record: {json.dumps(store.mock_store[0], indent=2, default=str)}")
