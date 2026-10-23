"""Build the Cloud Security Lab.

Step 1 (baseline): KMS key -> encrypted CloudTrail bucket -> multi-region trail
-> account-level S3 Block Public Access.

Safe to re-run: every resource is looked up first and only created if missing;
policies and settings are re-applied (the put calls are idempotent).
"""

import argparse
import json
import secrets

import boto3
from botocore.exceptions import ClientError

TAG_KEY, TAG_VALUE = "Project", "SecurityLab"
TRAIL_NAME = "seclab-trail"
KEY_ALIAS = "alias/seclab-cloudtrail"
TRAIL_BUCKET_PREFIX = "seclab-cloudtrail-"


def step(msg):
    print(f"\n==> {msg}")


def info(msg):
    print(f"    {msg}")


# ---------------------------------------------------------------- KMS key

def key_policy(account, trail_arn):
    """Key policy based on the AWS-documented CloudTrail template, scoped to our trail."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                # Without this the account itself could lose the ability to manage the key.
                "Sid": "EnableAccountAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudTrailEncrypt",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:GenerateDataKey*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceArn": trail_arn},
                    "StringLike": {
                        "kms:EncryptionContext:aws:cloudtrail:arn":
                            f"arn:aws:cloudtrail:*:{account}:trail/*"
                    },
                },
            },
            {
                "Sid": "AllowCloudTrailDescribeKey",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:DescribeKey",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                # Reading the logs requires kms:Decrypt; limit that to this account.
                "Sid": "AllowAccountToDecryptLogs",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:CallerAccount": account},
                    "StringLike": {
                        "kms:EncryptionContext:aws:cloudtrail:arn":
                            f"arn:aws:cloudtrail:*:{account}:trail/*"
                    },
                },
            },
        ],
    }


def ensure_kms_key(kms, account, trail_arn):
    step("KMS customer managed key for CloudTrail")
    try:
        key_id = kms.describe_key(KeyId=KEY_ALIAS)["KeyMetadata"]["KeyId"]
        info(f"exists: {KEY_ALIAS} ({key_id})")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        key_id = kms.create_key(
            Description="Security lab: encrypts CloudTrail logs",
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Policy=json.dumps(key_policy(account, trail_arn)),
            Tags=[{"TagKey": TAG_KEY, "TagValue": TAG_VALUE}],
        )["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=KEY_ALIAS, TargetKeyId=key_id)
        info(f"created: {KEY_ALIAS} ({key_id})")

    kms.put_key_policy(KeyId=key_id, PolicyName="default",
                       Policy=json.dumps(key_policy(account, trail_arn)))
    kms.enable_key_rotation(KeyId=key_id)
    info("key policy applied (CloudTrail scoped by aws:SourceArn), annual rotation enabled")
    return kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]


# ---------------------------------------------------------------- S3 bucket

def trail_bucket_policy(bucket, account, trail_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def find_bucket(s3, prefix, region):
    resp = s3.list_buckets(Prefix=prefix, BucketRegion=region)
    names = [b["Name"] for b in resp.get("Buckets", [])]
    return names[0] if names else None


def ensure_trail_bucket(s3, account, region, trail_arn, key_arn):
    step("Encrypted S3 bucket for CloudTrail logs")
    bucket = find_bucket(s3, TRAIL_BUCKET_PREFIX, region)
    if bucket:
        info(f"exists: {bucket}")
    else:
        bucket = TRAIL_BUCKET_PREFIX + secrets.token_hex(4)
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
            ObjectOwnership="BucketOwnerEnforced",  # ACLs disabled
        )
        s3.get_waiter("bucket_exists").wait(Bucket=bucket)
        info(f"created: {bucket} (object ownership: BucketOwnerEnforced, ACLs disabled)")

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    info("bucket-level Block Public Access: all four settings on")

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    info("versioning enabled (overwritten/deleted log objects are recoverable)")

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_arn},
            "BucketKeyEnabled": True,  # cuts KMS request volume (and cost)
        }]},
    )
    info("default encryption: SSE-KMS with the lab key, S3 Bucket Key on")

    s3.put_bucket_policy(Bucket=bucket,
                         Policy=json.dumps(trail_bucket_policy(bucket, account, trail_arn)))
    info("bucket policy: CloudTrail-only writes (scoped to our trail), deny non-TLS")

    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": TAG_KEY, "Value": TAG_VALUE}]})
    return bucket


# ---------------------------------------------------------------- CloudTrail

def ensure_trail(ct, bucket, key_arn):
    step("CloudTrail trail")
    settings = dict(
        Name=TRAIL_NAME,
        S3BucketName=bucket,
        IsMultiRegionTrail=True,
        IncludeGlobalServiceEvents=True,  # IAM/STS/etc. are recorded as global events
        EnableLogFileValidation=True,     # SHA-256 digest files, signed hourly
        KmsKeyId=key_arn,
    )
    existing = ct.describe_trails(trailNameList=[TRAIL_NAME], includeShadowTrails=False)["trailList"]
    if existing:
        ct.update_trail(**settings)
        info(f"exists, settings re-applied: {TRAIL_NAME}")
    else:
        ct.create_trail(**settings, TagsList=[{"Key": TAG_KEY, "Value": TAG_VALUE}])
        info(f"created: {TRAIL_NAME}")

    ct.start_logging(Name=TRAIL_NAME)
    status = ct.get_trail_status(Name=TRAIL_NAME)
    info(f"multi-region, global events, log file validation, SSE-KMS; "
         f"IsLogging={status['IsLogging']}")


# ---------------------------------------------------------------- Account BPA

def ensure_account_bpa(s3control, account):
    step("Account-level S3 Block Public Access")
    s3control.put_public_access_block(
        AccountId=account,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    info("all four settings on for every bucket in the account (not taggable; left on at teardown)")


# ---------------------------------------------------------------- main

def baseline(session):
    region = session.region_name
    account = session.client("sts").get_caller_identity()["Account"]
    trail_arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{TRAIL_NAME}"
    print(f"Account {account}, region {region}")

    key_arn = ensure_kms_key(session.client("kms"), account, trail_arn)
    bucket = ensure_trail_bucket(session.client("s3"), account, region, trail_arn, key_arn)
    ensure_trail(session.client("cloudtrail"), bucket, key_arn)
    ensure_account_bpa(session.client("s3control"), account)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--profile")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    baseline(session)
    print("\nBaseline complete.")


if __name__ == "__main__":
    main()
