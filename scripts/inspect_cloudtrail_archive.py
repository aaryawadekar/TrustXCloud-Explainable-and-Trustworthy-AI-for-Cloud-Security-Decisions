"""
Inspects the local CloudTrail archive from 'aws credentials info' folder.
This contains REAL CloudTrail logs from account 781133583461, region eu-north-1.
Used to understand the existing AWS infrastructure and event structure.
"""
import gzip
import json
import os

ARCHIVE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "aws credentials info",
    "781133583461_CloudTrail_eu-north-1_20260928T1225Z_B40E60UFQvlTUkj0.json.gz"
)

def main():
    print(f"Archive: {ARCHIVE_PATH}")
    with gzip.open(ARCHIVE_PATH, 'rb') as f:
        data = json.loads(f.read())

    records = data.get("Records", [])
    print(f"Total records in archive: {len(records)}\n")

    for i, r in enumerate(records):
        print(f"--- Record {i+1} of {len(records)} ---")
        print(f"  eventID:     {r.get('eventID')}")
        print(f"  eventTime:   {r.get('eventTime')}")
        print(f"  eventName:   {r.get('eventName')}")
        print(f"  eventSource: {r.get('eventSource')}")
        print(f"  awsRegion:   {r.get('awsRegion')}")
        uid = r.get("userIdentity", {})
        print(f"  identity:    type={uid.get('type')} / arn={uid.get('arn', '')}")
        print(f"  sourceIP:    {r.get('sourceIPAddress')}")
        print(f"  errorCode:   {r.get('errorCode')}")
        print(f"  userAgent:   {str(r.get('userAgent',''))[:80]}")
        print()

    # Show unique event names
    names = [r.get("eventName") for r in records]
    sources = [r.get("eventSource") for r in records]
    print("Unique eventNames:", sorted(set(names)))
    print("Unique eventSources:", sorted(set(sources)))

    # Full first record for structure inspection
    print("\n=== FULL FIRST RECORD (structure) ===")
    print(json.dumps(records[0], indent=2, default=str))

if __name__ == "__main__":
    main()
