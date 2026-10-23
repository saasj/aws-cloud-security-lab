"""Tear down the Cloud Security Lab: delete everything tagged Project=SecurityLab.

Discovery uses the Resource Groups Tagging API (S3, KMS, CloudTrail, EC2) plus
IAM's own APIs (the tagging API does not cover IAM). Every resource's tag is
re-checked immediately before it is deleted.

Order: trail -> buckets (all versions) -> IAM role -> boundary policy ->
security group -> KMS key (scheduled for deletion, 7-day minimum).
Account-level S3 Block Public Access is intentionally left on.
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

TAG_KEY, TAG_VALUE = "Project", "SecurityLab"
KMS_PENDING_DAYS = 7


def step(msg):
    print(f"\n==> {msg}")


def info(msg):
    print(f"    {msg}")


def tagged(tags, key="Key", value="Value"):
    return any(t[key] == TAG_KEY and t[value] == TAG_VALUE for t in tags)


# ---------------------------------------------------------------- discovery

def discover(session):
    found = {"trail": [], "bucket": [], "kms": [], "sg": [], "role": [], "policy": [], "other": []}

    tagging = session.client("resourcegroupstaggingapi")
    for page in tagging.get_paginator("get_resources").paginate(
            TagFilters=[{"Key": TAG_KEY, "Values": [TAG_VALUE]}]):
        for r in page["ResourceTagMappingList"]:
            arn = r["ResourceARN"]
            service = arn.split(":")[2]
            if service == "cloudtrail":
                found["trail"].append(arn)
            elif service == "s3":
                found["bucket"].append(arn.split(":::")[1])
            elif service == "kms":
                found["kms"].append(arn)
            elif service == "ec2" and ":security-group/" in arn:
                found["sg"].append(arn.split("/")[-1])
            else:
                found["other"].append(arn)

    iam = session.client("iam")
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if role["Path"].startswith("/aws-service-role/"):
                continue
            if tagged(iam.list_role_tags(RoleName=role["RoleName"])["Tags"]):
                found["role"].append(role["RoleName"])
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for pol in page["Policies"]:
            if tagged(iam.list_policy_tags(PolicyArn=pol["Arn"])["Tags"]):
                found["policy"].append(pol["Arn"])
    return found


# ---------------------------------------------------------------- deleters

def delete_trail(session, arn, dry):
    ct = session.client("cloudtrail", region_name=arn.split(":")[3])
    try:
        if not tagged(ct.list_tags(ResourceIdList=[arn])["ResourceTagList"][0].get("TagsList", [])):
            return info(f"SKIP {arn}: tag no longer present")
    except ct.exceptions.TrailNotFoundException:
        return info(f"gone already: {arn}")
    if dry:
        return info(f"would stop logging and delete trail {arn.split('/')[-1]}")
    ct.stop_logging(Name=arn)
    ct.delete_trail(Name=arn)
    info(f"stopped logging and deleted trail {arn.split('/')[-1]}")


def delete_bucket(session, name, dry):
    s3 = session.client("s3")
    try:
        if not tagged(s3.get_bucket_tagging(Bucket=name)["TagSet"]):
            return info(f"SKIP {name}: tag no longer present")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucket":
            return info(f"gone already: {name}")
        raise

    count = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
        batch = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                 for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        count += len(batch)
        if batch and not dry:
            for i in range(0, len(batch), 1000):
                s3.delete_objects(Bucket=name, Delete={"Objects": batch[i:i + 1000], "Quiet": True})
    if dry:
        return info(f"would delete {count} object versions/delete markers, then bucket {name}")
    s3.delete_bucket(Bucket=name)
    info(f"deleted {count} object versions/delete markers, then bucket {name}")


def delete_role(session, name, dry):
    iam = session.client("iam")
    if not tagged(iam.list_role_tags(RoleName=name)["Tags"]):
        return info(f"SKIP role {name}: tag no longer present")
    inline = iam.list_role_policies(RoleName=name)["PolicyNames"]
    attached = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
    profiles = [p["InstanceProfileName"]
                for p in iam.list_instance_profiles_for_role(RoleName=name)["InstanceProfiles"]]
    if dry:
        return info(f"would remove {len(inline)} inline / {len(attached)} attached policies, "
                    f"{len(profiles)} instance profiles, then delete role {name}")
    for p in inline:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    for arn in attached:
        iam.detach_role_policy(RoleName=name, PolicyArn=arn)
    for p in profiles:
        iam.remove_role_from_instance_profile(InstanceProfileName=p, RoleName=name)
    iam.delete_role(RoleName=name)
    info(f"removed {len(inline)} inline / {len(attached)} attached policies, deleted role {name}")


def delete_policy(session, arn, dry):
    iam = session.client("iam")
    if not tagged(iam.list_policy_tags(PolicyArn=arn)["Tags"]):
        return info(f"SKIP {arn}: tag no longer present")
    name = arn.split("/")[-1]
    if dry:
        return info(f"would delete policy {name} (and its non-default versions)")
    users = iam.list_entities_for_policy(PolicyArn=arn)
    boundary = iam.list_entities_for_policy(PolicyArn=arn, PolicyUsageFilter="PermissionsBoundary")
    if any(users[k] for k in ("PolicyRoles", "PolicyUsers", "PolicyGroups")) or \
            any(boundary[k] for k in ("PolicyRoles", "PolicyUsers")):
        return info(f"SKIP policy {name}: still attached or used as a boundary by an untagged entity")
    for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
        if not v["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
    iam.delete_policy(PolicyArn=arn)
    info(f"deleted policy {name}")


def delete_sg(session, group_id, dry):
    ec2 = session.client("ec2")
    try:
        group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            return info(f"gone already: {group_id}")
        raise
    if not tagged(group.get("Tags", [])):
        return info(f"SKIP {group_id}: tag no longer present")
    enis = ec2.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [group_id]}])["NetworkInterfaces"]
    if enis:
        return info(f"SKIP {group_id} ({group['GroupName']}): attached to {len(enis)} network interface(s)")
    if dry:
        return info(f"would delete security group {group_id} ({group['GroupName']})")
    ec2.delete_security_group(GroupId=group_id)
    info(f"deleted security group {group_id} ({group['GroupName']})")


def delete_kms_key(session, arn, dry):
    kms = session.client("kms", region_name=arn.split(":")[3])
    meta = kms.describe_key(KeyId=arn)["KeyMetadata"]
    if meta["KeyState"] == "PendingDeletion":
        return info(f"already pending deletion: {meta['KeyId']} (on {meta['DeletionDate']:%Y-%m-%d})")
    if not tagged(kms.list_resource_tags(KeyId=arn)["Tags"], key="TagKey", value="TagValue"):
        return info(f"SKIP {meta['KeyId']}: tag no longer present")
    aliases = [a["AliasName"] for a in kms.list_aliases(KeyId=meta["KeyId"])["Aliases"]]
    if dry:
        return info(f"would delete alias(es) {', '.join(aliases) or '-'} and schedule key "
                    f"{meta['KeyId']} for deletion in {KMS_PENDING_DAYS} days")
    for a in aliases:
        kms.delete_alias(AliasName=a)
    when = kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=KMS_PENDING_DAYS)["DeletionDate"]
    info(f"deleted alias(es) {', '.join(aliases) or '-'}; key {meta['KeyId']} deletes on {when:%Y-%m-%d} "
         f"(cancel with: aws kms cancel-key-deletion --key-id {meta['KeyId']})")


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--profile")
    parser.add_argument("--dry-run", action="store_true", help="show what would be deleted; change nothing")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    parser.add_argument("--keep-logs", action="store_true",
                        help="keep the CloudTrail log bucket and its KMS key (the trail is still deleted)")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    print(f"Account {account}, region {args.region}{'  [DRY RUN]' if args.dry_run else ''}")

    found = discover(session)
    if args.keep_logs:
        kept = [b for b in found["bucket"] if b.startswith("seclab-cloudtrail-")] + found["kms"]
        found["bucket"] = [b for b in found["bucket"] if not b.startswith("seclab-cloudtrail-")]
        found["kms"] = []
    else:
        kept = []

    step(f"Resources tagged {TAG_KEY}={TAG_VALUE}")
    labels = {"trail": "CloudTrail trail", "bucket": "S3 bucket", "role": "IAM role",
              "policy": "IAM policy", "sg": "Security group", "kms": "KMS key"}
    for kind, label in labels.items():
        for item in found[kind]:
            info(f"{label:<17} {item}")
    for item in kept:
        info(f"{'KEEP (--keep-logs)':<17} {item}")
    for item in found["other"]:
        info(f"{'UNHANDLED':<17} {item}  (not deleted by this script)")
    if not any(found[k] for k in labels):
        print("\nNothing to delete.")
        return

    if not args.dry_run and not args.yes:
        if input("\nType DELETE to permanently delete the resources above: ").strip() != "DELETE":
            print("Aborted; nothing was changed.")
            sys.exit(1)

    order = [("trail", delete_trail, "CloudTrail"), ("bucket", delete_bucket, "S3 buckets"),
             ("role", delete_role, "IAM roles"), ("policy", delete_policy, "IAM policies"),
             ("sg", delete_sg, "Security groups"), ("kms", delete_kms_key, "KMS keys")]
    errors = 0
    for kind, fn, title in order:
        if not found[kind]:
            continue
        step(title)
        for item in found[kind]:
            try:
                fn(session, item, args.dry_run)
            except ClientError as e:
                errors += 1
                err = e.response["Error"]
                info(f"ERROR {item}: {err['Code']}: {err['Message'][:160]}")

    step("Account-level S3 Block Public Access")
    info("left ON (account guardrail, not a lab resource)")
    print(f"\n{'Dry run complete; nothing was changed.' if args.dry_run else 'Teardown complete.'}"
          + (f"  {errors} error(s)." if errors else ""))
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
