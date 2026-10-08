# TrustXCloud: Handover Package for Parth Gourshettiwar
**Subject:** Live AWS CloudTrail Log Collection, Continuous S3 Storage & Daily `.json.gz` Logs  
**Author:** Vedant Sonawane  
**Target Teammate:** Parth Gourshettiwar (`parthgourshettiwar@gmail.com` / Backend & Cloud Lead)  
**Git Branch:** `feat/cloudtrail-pipeline-latest` (Synchronized with latest `origin/main`)  
**Live AWS Account ID:** `663001881461`  
**Live S3 Destination:** `s3://trustxcloud-security-logs-663001881461`  
**Live Trail ARN:** `arn:aws:cloudtrail:us-east-1:663001881461:trail/trustxcloud-multi-region-trail`  
**Date:** October 8, 2026  

---

## 1. Executive Summary

Hi Parth,

The **Live AWS CloudTrail Log Collection & Continuous S3 Storage** pipeline is now fully set up, authenticated, and verified against a live AWS account:

1. **Live Continuous S3 Storage Bucket Created**: 
   `s3://trustxcloud-security-logs-663001881461`
   - Configured with Server-Side Encryption (AES-256 SSE-S3).
   - Public Access Block fully enabled (100% private).
   - Resource policy applied granting least-privilege `s3:GetBucketAcl` and `s3:PutObject` to `cloudtrail.amazonaws.com`.
2. **Multi-Region CloudTrail Logging Active**: 
   `arn:aws:cloudtrail:us-east-1:663001881461:trail/trustxcloud-multi-region-trail`
   - Multi-region trail enabled across all AWS regions.
   - Global service events enabled (captures global IAM events in `us-east-1`).
   - Log file validation enabled (cryptographic SHA-256 digests).
   - Logging is active and delivering to S3.
3. **Daily Live CloudTrail `.json.gz` Files Generated & Synced**:
   - Total of 11 compressed `.json.gz` archives for today (`2026-10-08`) containing **74 events**.
   - Contains actual real-time AWS API events from account `663001881461` (including `PutBucketPolicy`, `CreateAccessKey`, `ListAccessKeys`, `ListMFADevices`, `DescribeOrganization`, `GetAccountName`) combined with the benchmark threat vectors.
   - Synchronized directly into the live S3 bucket `s3://trustxcloud-security-logs-663001881461/AWSLogs/663001881461/CloudTrail/us-east-1/2026/10/08/` as well as packaged in local folders and ZIP/TAR archives.
4. **Backend Ingestion Ready**:
   - `backend/services/events_service.py` natively unpacks `.json.gz` files and directories in memory (tested and validated: 74 events loaded cleanly).

---

## 2. Live Infrastructure & Provisioning

All provisioning scripts and IaC are ready in `aws/`:

* **Automated Python/Boto3**: [`aws/setup_cloudtrail_s3.py`](file:///d:/TrustXCloud_repo/aws/setup_cloudtrail_s3.py)
* **Production Terraform**: [`aws/terraform/cloudtrail_s3.tf`](file:///d:/TrustXCloud_repo/aws/terraform/cloudtrail_s3.tf)
* **AWS CLI Shell Scripts**: [`aws/scripts/setup_cloudtrail_s3.sh`](file:///d:/TrustXCloud_repo/aws/scripts/setup_cloudtrail_s3.sh) / [`.bat`](file:///d:/TrustXCloud_repo/aws/scripts/setup_cloudtrail_s3.bat)
* **CloudFormation Template**: [`aws/cloudformation/cloudtrail_s3_template.json`](file:///d:/TrustXCloud_repo/aws/cloudformation/cloudtrail_s3_template.json)
* **Bucket Policy**: [`aws/policies/cloudtrail_s3_bucket_policy.json`](file:///d:/TrustXCloud_repo/aws/policies/cloudtrail_s3_bucket_policy.json)

---

## 3. Daily CloudTrail Log Collection (`.json.gz` Files)

### How to Collect Any Day's Logs
```bash
python aws/collect_daily_cloudtrail.py --date 2026-10-08
```
This automatically connects to AWS STS, queries live S3 and CloudTrail LookupEvents, batches records, creates `.json.gz` archives, and syncs them to S3.

### File Locations for Today (`2026-10-08`)

1. **Live AWS S3 Bucket Prefix:**
   `s3://trustxcloud-security-logs-663001881461/AWSLogs/663001881461/CloudTrail/us-east-1/2026/10/08/`

2. **Canonical Local S3 Structure:**
   `data/s3_storage/AWSLogs/663001881461/CloudTrail/us-east-1/2026/10/08/`

3. **Daily Export Folder:**
   `data/cloudtrail_logs_daily/2026-10-08/`

4. **Bundled Downloadable Archives:**
   - **ZIP Archive:** `data/cloudtrail_logs_daily/cloudtrail_logs_2026-10-08.zip`
   - **TAR.GZ Archive:** `data/cloudtrail_logs_daily/cloudtrail_logs_2026-10-08.tar.gz`

---

## 4. How to Run the FastAPI Backend with Live Logs

In your `.env` or terminal:
```bash
RAW_EVENTS_PATH=data/cloudtrail_logs_daily/2026-10-08 uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend automatically detects the directory, decompresses the 11 `.json.gz` archives in memory, and serves all 74 events through your `/api/v1/events` endpoint!

You can also run the streaming parser directly:
```bash
python aws/s3_cloudtrail_parser.py --dir data/cloudtrail_logs_daily/2026-10-08
```

---

## 5. Ready-to-Send Message for Parth

> **Hey Parth,**
>
> The CloudTrail collection pipeline is now live on our AWS account (`663001881461`)! All code and archives are on branch `feat/cloudtrail-pipeline-latest` (based on the latest `origin/main`).
>
> **What's Done:**
> 1. **Live S3 Storage**: `s3://trustxcloud-security-logs-663001881461` is active, private, and encrypted.
> 2. **Multi-Region Trail**: `arn:aws:cloudtrail:us-east-1:663001881461:trail/trustxcloud-multi-region-trail` is running with global IAM events & log validation.
> 3. **Today's Logs (`2026-10-08`)**: 11 official `.json.gz` archives containing 74 events (both live AWS console activity and attack vectors) generated and synced to S3.
> 4. **Backend Ready**: `EventsService` is updated to load `.json.gz` folders directly. Run with `RAW_EVENTS_PATH=data/cloudtrail_logs_daily/2026-10-08`.
> 5. **Documentation**: Detailed guide is in [`HANDOVER_PARTH_CLOUDTRAIL.md`](file:///d:/TrustXCloud_repo/HANDOVER_PARTH_CLOUDTRAIL.md).
