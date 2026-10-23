# AWS Cloud Security Lab

A hands-on lab in a single AWS sandbox account (us-east-2): apply a security
baseline, deploy deliberately misconfigured resources, then detect them with
Python/boto3 audit tooling and review CloudTrail for risky activity.

Everything is free-tier or near-free (~$1/month for one KMS key). No EC2
instances, GuardDuty, Security Hub, or AWS Config. All lab resources are tagged
`Project=SecurityLab`.

> Account IDs, key IDs and bucket suffixes in this README are redacted
> (`111122223333`, `<key-id>`, `xxxxxxxx`).

## Requirements

- Python 3.12+ and `pip install -r requirements.txt`
  (`boto3[crt]` — the CRT extra is needed for `aws login` credentials)
- AWS credentials with admin rights in a sandbox account

## Step 1 — Baseline controls (`setup_lab.py`)

| Control | Implementation | Why |
|---|---|---|
| KMS customer managed key | `alias/seclab-cloudtrail`, annual rotation; key policy lets CloudTrail encrypt only for our trail (`aws:SourceArn`), decrypt only within this account | Customer-controlled key, separation of who can write vs. read logs |
| CloudTrail log bucket | Bucket-level Block Public Access, ACLs disabled (BucketOwnerEnforced), versioning, SSE-KMS default with S3 Bucket Key | Log integrity and confidentiality |
| Bucket policy | CloudTrail-only writes scoped to our trail; deny any request where `aws:SecureTransport` is false | Confused-deputy protection; encryption in transit |
| CloudTrail trail | `seclab-trail`: multi-region, global service events, log file validation, SSE-KMS | Complete, tamper-evident audit trail |
| Account S3 Block Public Access | All four settings on | Account-wide guardrail against public buckets |

IAM Access Analyzer is **not** used: an Organizations SCP on this managed
account explicitly denies `access-analyzer:*`. `audit.py` analyses IAM policies
directly instead.

```
python setup_lab.py            # --region us-east-2 (default), --profile NAME
```

## Verification

Each control was confirmed independently with the AWS CLI rather than by
trusting `setup_lab.py`'s own output.

### CloudTrail trail settings

```
$ aws cloudtrail get-trail --name seclab-trail \
    --query 'Trail.[IsMultiRegionTrail,IncludeGlobalServiceEvents,LogFileValidationEnabled,KmsKeyId]' --output text
True    True    True    arn:aws:kms:us-east-2:111122223333:key/<key-id>

$ aws cloudtrail get-trail-status --name seclab-trail --query IsLogging
true
```

### Log delivery and log file validation

Confirms CloudTrail can actually write through the bucket policy and KMS key
policy, and that digest files verify. Immediately after setup CloudTrail had
created both prefixes; the first log files arrive within ~15 minutes and the
first digest within ~1 hour.

```
$ aws s3api list-objects-v2 --bucket seclab-cloudtrail-xxxxxxxx --query 'Contents[].Key' --output text
AWSLogs/111122223333/CloudTrail-Digest/    AWSLogs/111122223333/CloudTrail/

$ aws cloudtrail get-trail-status --name seclab-trail \
    --query '[LatestDeliveryTime,LatestDeliveryError,LatestDigestDeliveryTime]'
# PENDING: re-run after first delivery; expect timestamps and LatestDeliveryError = null

$ aws cloudtrail validate-logs \
    --trail-arn arn:aws:cloudtrail:us-east-2:111122223333:trail/seclab-trail \
    --start-time <setup time, ISO 8601>
# PENDING: expect "... digest files valid" and "... log files valid"
```

### Bucket encryption, versioning, Block Public Access

```
$ aws s3api get-bucket-encryption --bucket seclab-cloudtrail-xxxxxxxx \
    --query 'ServerSideEncryptionConfiguration.Rules[0]'
{
    "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-2:111122223333:key/<key-id>"
    },
    "BucketKeyEnabled": true,
    "BlockedEncryptionTypes": { "EncryptionType": ["SSE-C"] }
}

$ aws s3api get-bucket-versioning --bucket seclab-cloudtrail-xxxxxxxx --output text
Enabled

$ aws s3api get-public-access-block --bucket seclab-cloudtrail-xxxxxxxx --output text
PUBLICACCESSBLOCKCONFIGURATION  True  True  True  True
```

### Non-TLS requests are denied

A plain-HTTP request from an admin principal is still refused — the explicit
`Deny` on `aws:SecureTransport = false` overrides any `Allow`.

```
$ aws s3api list-objects-v2 --bucket seclab-cloudtrail-xxxxxxxx \
    --endpoint-url http://s3.us-east-2.amazonaws.com
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListObjectsV2 operation: User: arn:aws:sts::111122223333:assumed-role/... is not authorized ...
```

### KMS key rotation

(`get-key-rotation-status` does not accept an alias; use the key ID.)

```
$ aws kms get-key-rotation-status --key-id <key-id> \
    --query '[KeyRotationEnabled,RotationPeriodInDays]' --output text
True    365
```

### Account-level S3 Block Public Access

```
$ aws s3control get-public-access-block --account-id 111122223333 --output text
PUBLICACCESSBLOCKCONFIGURATION  True  True  True  True
```

### Idempotency: `setup_lab.py` re-run

The script was run a second time to prove it is safe to repeat: every resource
was found rather than duplicated, and settings were re-applied.

```
$ python setup_lab.py
    exists: alias/seclab-cloudtrail (<key-id>)
    exists: seclab-cloudtrail-xxxxxxxx
    exists, settings re-applied: seclab-trail
Baseline complete.
```
