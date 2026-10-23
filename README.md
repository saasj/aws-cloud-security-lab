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

## Step 2 — Deliberately misconfigured test resources

| Resource | Misconfiguration (what `audit.py` should flag) | Safety limit |
|---|---|---|
| `seclab-weak-bucket-xxxxxxxx` | No versioning, default SSE-S3 only (no customer-managed key), no TLS-only bucket policy | Still private: bucket and account Block Public Access |
| `SecLab-OverPrivilegedRole` | Inline policy `Allow` `Action: *` on `Resource: *` | Trust policy: own account only. Permissions boundary `SecLab-DenyAllBoundary` denies everything, so effective permissions are none |
| `seclab-open-ssh` security group | Ingress tcp/22 from `0.0.0.0/0` | Attached to no network interface |

S3 has encrypted every new bucket with SSE-S3 since January 2023, and that can't
be turned off. A truly unencrypted bucket is therefore no longer possible; the
realistic finding today is "no customer-managed KMS key".

```
python setup_lab.py                   # both steps (default: --step all)
python setup_lab.py --step baseline   # Step 1 only
python setup_lab.py --step misconfig  # Step 2 only
# options: --region us-east-2 (default), --profile NAME
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
created both prefixes; the first log file arrived ~15 minutes later and the
first digest within the hour.

```
$ aws s3api list-objects-v2 --bucket seclab-cloudtrail-xxxxxxxx --query 'Contents[].Key' --output text
AWSLogs/111122223333/CloudTrail-Digest/    AWSLogs/111122223333/CloudTrail/

$ aws cloudtrail get-trail-status --name seclab-trail \
    --query '[LatestDeliveryTime,LatestDeliveryError,LatestDigestDeliveryTime]' --output text
2026-10-23T16:16:33-04:00    None    2026-10-23T16:13:07-04:00

$ aws cloudtrail validate-logs \
    --trail-arn arn:aws:cloudtrail:us-east-2:111122223333:trail/seclab-trail \
    --start-time 2026-10-23T19:30:00Z
Results found for 2026-10-23T19:30:00Z to 2026-10-23T19:45:14Z:
1/1 digest files valid
```

`LatestDeliveryError` is `None`, so both the bucket policy and the KMS key
policy allow CloudTrail to write. The first digest's signature verifies. That
digest covers a window that ended before the first log file was delivered, so
it references no log files yet; later digests also validate the SHA-256 hash of
each log file.

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

### Step 2: weak bucket

```
$ aws s3api get-bucket-versioning --bucket seclab-weak-bucket-xxxxxxxx
                                    # empty output = versioning never enabled
$ aws s3api get-bucket-encryption --bucket seclab-weak-bucket-xxxxxxxx \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text
AES256                              # SSE-S3 default, not KMS
$ aws s3api get-bucket-policy --bucket seclab-weak-bucket-xxxxxxxx
An error occurred (NoSuchBucketPolicy) ...   # no TLS-only policy
```

### Step 2: over-privileged role is neutered by its boundary

The IAM policy simulator evaluates the identity policy *and* the permissions
boundary. The inline policy allows everything, but the boundary's explicit deny
wins:

```
$ aws iam get-role-policy --role-name SecLab-OverPrivilegedRole \
    --policy-name SecLab-AllowEverything --query 'PolicyDocument.Statement'
[ { "Effect": "Allow", "Action": "*", "Resource": "*" } ]

$ aws iam get-role --role-name SecLab-OverPrivilegedRole \
    --query 'Role.[PermissionsBoundary.PermissionsBoundaryArn,AssumeRolePolicyDocument.Statement[0].Principal.AWS]' --output text
arn:aws:iam::111122223333:policy/SecLab-DenyAllBoundary    arn:aws:iam::111122223333:root

$ aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::111122223333:role/SecLab-OverPrivilegedRole \
    --action-names s3:ListAllMyBuckets iam:CreateUser ec2:RunInstances \
    --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
s3:ListAllMyBuckets    explicitDeny
iam:CreateUser         explicitDeny
ec2:RunInstances       explicitDeny
```

### Step 2: open-SSH security group is attached to nothing

```
$ aws ec2 describe-security-groups --group-ids sg-xxxxxxxx \
    --query 'SecurityGroups[0].IpPermissions[].[IpProtocol,FromPort,ToPort,IpRanges[0].CidrIp]' --output text
tcp    22    22    0.0.0.0/0

$ aws ec2 describe-network-interfaces --filters Name=group-id,Values=sg-xxxxxxxx \
    --query 'length(NetworkInterfaces)'
0
```

### Tagging

```
$ aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=SecurityLab \
    --query 'ResourceTagMappingList[].ResourceARN' --output text
arn:aws:s3:::seclab-cloudtrail-xxxxxxxx    arn:aws:s3:::seclab-weak-bucket-xxxxxxxx
arn:aws:kms:us-east-2:111122223333:key/<key-id>
arn:aws:cloudtrail:us-east-2:111122223333:trail/seclab-trail
arn:aws:ec2:us-east-2:111122223333:security-group/sg-xxxxxxxx
```

The IAM role and boundary policy are tagged too, but the Resource Groups
Tagging API doesn't cover IAM. Cleanup has to find them through IAM's own API.

### Idempotency: `setup_lab.py` re-run

After each step the script was run again to prove it is safe to repeat: every
resource was found rather than duplicated, and settings were re-applied.

```
$ python setup_lab.py
    exists: alias/seclab-cloudtrail (<key-id>)
    exists: seclab-cloudtrail-xxxxxxxx
    exists, settings re-applied: seclab-trail
Baseline complete.
    exists: seclab-weak-bucket-xxxxxxxx
    exists: boundary policy SecLab-DenyAllBoundary
    exists: role SecLab-OverPrivilegedRole, boundary re-applied
    exists: seclab-open-ssh (sg-xxxxxxxx)
    ingress rule tcp/22 from 0.0.0.0/0 already present
Misconfigured test resources complete.
```
