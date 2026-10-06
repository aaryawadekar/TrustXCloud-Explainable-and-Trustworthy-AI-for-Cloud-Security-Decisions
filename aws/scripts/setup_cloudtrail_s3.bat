@echo off
REM ==============================================================================
REM TrustXCloud: Automated AWS CloudTrail & Continuous S3 Storage Provisioning (Windows)
REM ==============================================================================

set REGION=us-east-1
set TRAIL_NAME=trustxcloud-multi-region-trail

echo [*] Checking AWS Identity...
for /f "tokens=*" %%i in ('aws sts get-caller-identity --query Account --output text') do set ACCOUNT_ID=%%i

if "%ACCOUNT_ID%"=="" (
    echo [-] Failed to determine AWS Account ID. Ensure AWS CLI is configured.
    exit /b 1
)

echo [+] AWS Account ID: %ACCOUNT_ID% in Region: %REGION%
set BUCKET_NAME=trustxcloud-security-logs-%ACCOUNT_ID%

echo [*] Creating Amazon S3 Bucket: %BUCKET_NAME%...
aws s3api create-bucket --bucket %BUCKET_NAME% --region %REGION%

echo [*] Enabling S3 Bucket Encryption & Public Access Block...
aws s3api put-bucket-encryption --bucket %BUCKET_NAME% --server-side-encryption-configuration "{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}"
aws s3api put-public-access-block --bucket %BUCKET_NAME% --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-versioning --bucket %BUCKET_NAME% --versioning-configuration Status=Enabled

echo [*] Applying CloudTrail S3 Bucket Policy...
aws s3api put-bucket-policy --bucket %BUCKET_NAME% --policy file://../policies/cloudtrail_s3_bucket_policy.json

echo [*] Creating Multi-Region CloudTrail: %TRAIL_NAME%...
aws cloudtrail create-trail --name %TRAIL_NAME% --s3-bucket-name %BUCKET_NAME% --is-multi-region-trail --include-global-service-events --enable-log-file-validation

echo [*] Starting CloudTrail Logging...
aws cloudtrail start-logging --name %TRAIL_NAME%

echo [+] CloudTrail Continuous S3 Log Delivery Active!
echo     Trail Name:  %TRAIL_NAME%
echo     S3 Bucket:   s3://%BUCKET_NAME%/AWSLogs/%ACCOUNT_ID%/CloudTrail/
