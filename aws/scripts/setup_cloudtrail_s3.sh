#!/bin/bash
# ==============================================================================
# TrustXCloud: Automated AWS CloudTrail & Continuous S3 Storage Provisioning
# ==============================================================================

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
TRAIL_NAME="trustxcloud-multi-region-trail"

echo "[*] Checking AWS Identity..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "[+] AWS Account ID: ${ACCOUNT_ID} in Region: ${REGION}"

BUCKET_NAME="trustxcloud-security-logs-${ACCOUNT_ID}"

echo "[*] Creating Amazon S3 Bucket: ${BUCKET_NAME}..."
if [ "${REGION}" == "us-east-1" ]; then
    aws s3api create-bucket \
        --bucket "${BUCKET_NAME}" \
        --region "${REGION}" || true
else
    aws s3api create-bucket \
        --bucket "${BUCKET_NAME}" \
        --region "${REGION}" \
        --create-bucket-configuration LocationConstraint="${REGION}" || true
fi

echo "[*] Enabling S3 Bucket Encryption & Public Access Block..."
aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

aws s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-versioning \
    --bucket "${BUCKET_NAME}" \
    --versioning-configuration Status=Enabled

echo "[*] Applying CloudTrail S3 Bucket Policy..."
POLICY_DOC=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${BUCKET_NAME}",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
                }
            }
        }
    ]
}
EOF
)

aws s3api put-bucket-policy --bucket "${BUCKET_NAME}" --policy "${POLICY_DOC}"

echo "[*] Creating Multi-Region CloudTrail: ${TRAIL_NAME}..."
aws cloudtrail create-trail \
    --name "${TRAIL_NAME}" \
    --s3-bucket-name "${BUCKET_NAME}" \
    --is-multi-region-trail \
    --include-global-service-events \
    --enable-log-file-validation

echo "[*] Starting CloudTrail Logging..."
aws cloudtrail start-logging --name "${TRAIL_NAME}"

echo "[+] CloudTrail Continuous S3 Log Delivery Active!"
echo "    Trail Name:  ${TRAIL_NAME}"
echo "    S3 Bucket:   s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/"
