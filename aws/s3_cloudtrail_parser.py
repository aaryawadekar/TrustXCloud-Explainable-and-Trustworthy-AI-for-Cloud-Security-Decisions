"""
AWS S3 CloudTrail Ingestion & Streaming Parser (Boto3).

Fetches CloudTrail compressed JSON (.json.gz) archives from S3, decompresses them
in memory, extracts API records, and forwards them to the Explainable AI pipeline.
Includes an offline/mock fallback mode so beginners can run it without live AWS credentials.
"""

import os
import sys
import gzip
import json
import io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import boto3
    from botocore.exceptions import NoCredentialsError, ClientError
except ImportError:
    boto3 = None
    NoCredentialsError = None
    ClientError = None

from src.predict_and_explain import CloudSecurityAnalyzer

class S3CloudTrailParser:
    def __init__(self, bucket_name: str = "example-cloudtrail-logs-bucket", region: str = "us-east-1"):
        self.bucket_name = bucket_name
        self.region = region
        self.analyzer = CloudSecurityAnalyzer()
        
        if boto3 is None:
            print("[*] Note: boto3 not installed.")
            print("    Running S3 parser in Local Simulation Mode using sample CloudTrail traces.\n")
            self.s3_client = None
            self.is_live = False
            return

        try:
            self.s3_client = boto3.client("s3", region_name=region)
            # Test credentials check
            self.s3_client.list_buckets()
            self.is_live = True
            print(f"[*] Connected to AWS S3. Listening on bucket: s3://{bucket_name}")
        except Exception as e:
            print(f"[*] Note: AWS credentials not configured ({e}).")
            print("    Running S3 parser in Local Simulation Mode using sample CloudTrail traces.\n")
            self.s3_client = None
            self.is_live = False

    def process_s3_object(self, key: str):
        """
        Downloads a .json.gz file from S3 and processes each CloudTrail record.
        """
        if not self.is_live:
            return self._simulate_local_processing()
            
        print(f"[*] Fetching object from s3://{self.bucket_name}/{key}...")
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=key)
            compressed_bytes = response["Body"].read()
            
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_bytes), mode="rb") as gz:
                content = gz.read().decode("utf-8")
                data = json.loads(content)
                
            records = data.get("Records", [])
            print(f"  [+] Unpacked {len(records)} CloudTrail records. Running XAI analysis...")
            for idx, record in enumerate(records):
                print(f"\n--- Analyzing Record {idx+1}/{len(records)}: {record.get('eventName')} ---")
                res = self.analyzer.analyze_event(record)
                self.analyzer.print_decision_report(res)
                
        except Exception as e:
            print(f"[-] S3 processing error: {e}")

    def _simulate_local_processing(self):
        """
        Demonstrates S3 archive parsing using local raw CloudTrail sample files.
        """
        raw_samples_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "processed", "sample_raw_events.json"
        )
        if not os.path.exists(raw_samples_path):
            print("[-] No local sample traces found. Run data/generate_dataset.py first.")
            return
            
        with open(raw_samples_path, "r") as f:
            data = json.load(f)
            
        records = data.get("Records", [])[:3]
        print(f"[*] Simulating S3 stream ingestion on {len(records)} CloudTrail records...")
        
        for idx, record in enumerate(records):
            print(f"\n[S3 Ingestion Stream] Processing Event {idx+1}: {record.get('eventName')} by {record.get('userIdentity', {}).get('userName')}")
            res = self.analyzer.analyze_event(record)
            self.analyzer.print_decision_report(res)

if __name__ == "__main__":
    parser = S3CloudTrailParser(bucket_name="my-cloudtrail-bucket")
    parser.process_s3_object("AWSLogs/123456789012/CloudTrail/us-east-1/2026/04/10/sample_log.json.gz")
