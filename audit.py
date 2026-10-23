"""Audit an AWS account's security configuration and print a pass/fail report.

Read-only. Checks CloudTrail, S3 (account and bucket level), IAM (permission
policies, trust policies, root and user credentials, password policy) and EC2
security groups. IAM Access Analyzer is not used (blocked by an SCP in the lab
account); IAM policies are analysed directly instead.

Exit code: 1 if any check FAILs, 2 if a check could not run (ERROR), else 0.
"""

import argparse
import csv
import io
import json
import re
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

PASS, FAIL, WARN, ERROR = "PASS", "FAIL", "WARN", "ERROR"

# Service wildcards on Resource "*" that allow privilege escalation or
# tampering with security controls are FAILs; other service wildcards are WARNs.
HIGH_RISK_SERVICES = {"iam", "sts", "kms", "organizations", "cloudtrail", "account"}
BROAD_AWS_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess": FAIL,
    "arn:aws:iam::aws:policy/IAMFullAccess": FAIL,
    "arn:aws:iam::aws:policy/PowerUserAccess": WARN,
}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
KEY_MAX_AGE_DAYS = 90


@dataclass
class Finding:
    status: str
    check: str
    resource: str
    detail: str
    cis: str = ""


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def as_doc(doc):
    """IAM returns policy documents URL-encoded; boto3 usually decodes them, but not always."""
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return doc


def guarded(section):
    """Turn an AWS API error inside a check into an ERROR finding instead of a crash."""
    def wrap(fn):
        def run(*args, **kwargs):
            try:
                return list(fn(*args, **kwargs))
            except ClientError as e:
                err = e.response["Error"]
                return [Finding(ERROR, section, "-", f"{err['Code']}: {err['Message'][:160]}")]
        return run
    return wrap


# ---------------------------------------------------------------- CloudTrail

@guarded("CT")
def check_cloudtrail(session, region):
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
    if not trails:
        yield Finding(FAIL, "CT-1", "-", "No CloudTrail trail covers this region", "3.1")
        return

    good_multi_region = False
    for t in trails:
        name = t["Name"]
        home = session.client("cloudtrail", region_name=t["HomeRegion"])
        logging_on = home.get_trail_status(Name=t["TrailARN"])["IsLogging"]
        multi = t.get("IsMultiRegionTrail", False)
        good_multi_region |= logging_on and multi

        yield Finding(PASS if logging_on else FAIL, "CT-2", name,
                      "Trail is logging" if logging_on else "Trail exists but logging is stopped", "3.1")
        yield Finding(PASS if multi else FAIL, "CT-3", name,
                      "Multi-region trail" if multi else "Single-region trail only", "3.1")
        glob = t.get("IncludeGlobalServiceEvents", False)
        yield Finding(PASS if glob else FAIL, "CT-4", name,
                      "Records global service events (IAM, STS)" if glob
                      else "Global service events (IAM, STS) not recorded")
        lfv = t.get("LogFileValidationEnabled", False)
        yield Finding(PASS if lfv else FAIL, "CT-5", name,
                      "Log file validation enabled" if lfv else "Log file validation disabled", "3.2")
        kms = t.get("KmsKeyId")
        yield Finding(PASS if kms else FAIL, "CT-6", name,
                      "Logs encrypted with SSE-KMS" if kms else "Logs not encrypted with a KMS key", "3.5")

    yield Finding(PASS if good_multi_region else FAIL, "CT-1", "account",
                  "At least one multi-region trail is logging" if good_multi_region
                  else "No multi-region trail is logging", "3.1")


# ---------------------------------------------------------------- S3

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def bpa_result(config):
    off = [f for f in BPA_FLAGS if not config.get(f)]
    return (PASS, "All four Block Public Access settings on") if not off \
        else (FAIL, "Block Public Access off: " + ", ".join(off))


@guarded("S3")
def check_s3_account(session, account):
    s3control = session.client("s3control")
    try:
        config = s3control.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
        status, detail = bpa_result(config)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        status, detail = FAIL, "Account-level Block Public Access not configured"
    yield Finding(status, "S3-1", "account", detail, "2.1.4")


def denies_insecure_transport(policy):
    for st in as_list(policy.get("Statement")):
        if st.get("Effect") != "Deny":
            continue
        actions = [a.lower() for a in as_list(st.get("Action"))]
        if not ({"*", "s3:*"} & set(actions)):
            continue
        for operator in ("Bool", "BoolIfExists"):
            value = st.get("Condition", {}).get(operator, {}).get("aws:SecureTransport")
            if str(as_list(value)[0] if as_list(value) else "").lower() == "false":
                return True
    return False


@guarded("S3")
def check_s3_buckets(session, region):
    s3 = session.client("s3", region_name=region)
    buckets = [b["Name"]
               for page in s3.get_paginator("list_buckets").paginate(BucketRegion=region)
               for b in page.get("Buckets", [])]
    if not buckets:
        yield Finding(PASS, "S3-2", "-", f"No buckets in {region}")
        return

    for name in buckets:
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            status, detail = bpa_result(config)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            status, detail = FAIL, "Bucket-level Block Public Access not configured"
        yield Finding(status, "S3-2", name, detail, "2.1.4")

        versioning = s3.get_bucket_versioning(Bucket=name).get("Status", "Never enabled")
        yield Finding(PASS if versioning == "Enabled" else FAIL, "S3-3", name,
                      f"Versioning: {versioning}")

        rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        if algo.startswith("aws:kms"):
            yield Finding(PASS, "S3-4", name, f"Default encryption: {algo} (KMS key)")
        else:
            yield Finding(WARN, "S3-4", name,
                          f"Default encryption: {algo} (SSE-S3 only, no customer-managed key)")

        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            ok = denies_insecure_transport(policy)
            detail = "Bucket policy denies non-TLS requests" if ok \
                else "Bucket policy does not deny non-TLS requests"
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            ok, detail = False, "No bucket policy, so non-TLS requests are not denied"
        yield Finding(PASS if ok else FAIL, "S3-5", name, detail, "2.1.1")


# ---------------------------------------------------------------- IAM

def permission_issues(doc):
    """Return (status, reason) pairs for overly broad Allow statements."""
    issues = []
    for st in as_list(as_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        cond = " (has a Condition)" if st.get("Condition") else ""
        broad_resource = "*" in as_list(st.get("Resource")) or "NotResource" in st
        if not broad_resource:
            continue
        if "NotAction" in st:
            issues.append((FAIL, f"Allow with NotAction on all resources (allows everything not listed){cond}"))
        actions = [a.lower() for a in as_list(st.get("Action"))]
        if "*" in actions:
            issues.append((FAIL, f'Allow "Action": "*" on "Resource": "*" (full admin){cond}'))
            continue
        for a in actions:
            if a.endswith(":*"):
                service = a.split(":")[0]
                severity = FAIL if service in HIGH_RISK_SERVICES else WARN
                issues.append((severity, f'Allow "{a}" on "Resource": "*"{cond}'))
    return issues


def principal_accounts(aws_principals):
    for p in aws_principals:
        if p == "*":
            yield "*"
        elif re.fullmatch(r"\d{12}", p):
            yield p
        elif p.startswith("arn:"):
            yield p.split(":")[4]


def trust_issues(doc, account):
    issues = []
    for st in as_list(as_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        aws = as_list(principal.get("AWS")) if isinstance(principal, dict) else as_list(principal)
        cond_keys = {k.lower() for ops in st.get("Condition", {}).values() for k in ops}
        mitigated = bool(cond_keys & {"sts:externalid", "aws:principalorgid", "aws:sourceaccount"})
        for acct in set(principal_accounts(aws)):
            if acct == "*":
                if st.get("Condition"):
                    issues.append((WARN, 'Trusts Principal "*" (restricted only by a Condition)'))
                else:
                    issues.append((FAIL, 'Trusts Principal "*" with no Condition: anyone can assume it'))
            elif acct != account and not mitigated:
                issues.append((WARN, f"Trusts external account {acct} with no sts:ExternalId "
                                     "or aws:PrincipalOrgID condition"))
    return issues


@guarded("IAM")
def check_iam_policies(session, account):
    iam = session.client("iam")
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Group", "Role", "LocalManagedPolicy"]):
        for key in details:
            details[key].extend(page.get(key, []))

    perm_findings, trust_findings = [], []

    # Customer managed policies: analyse the default version.
    for pol in details["Policies"]:
        doc = next(v["Document"] for v in pol["PolicyVersionList"] if v["IsDefaultVersion"])
        attached = pol.get("AttachmentCount", 0)
        for status, reason in permission_issues(doc):
            if not attached:
                status, reason = WARN, reason + " (policy not attached)"
            perm_findings.append(Finding(status, "IAM-1", f"policy/{pol['PolicyName']}", reason, "1.16"))

    principals = (
        [("user", u["UserName"], u.get("UserPolicyList", []), u, None) for u in details["UserDetailList"]]
        + [("group", g["GroupName"], g.get("GroupPolicyList", []), g, None) for g in details["GroupDetailList"]]
        + [("role", r["RoleName"], r.get("RolePolicyList", []), r, r) for r in details["RoleDetailList"]]
    )
    for kind, name, inline, entity, role in principals:
        if entity.get("Path", "").startswith("/aws-service-role/"):
            continue  # service-linked roles are managed by AWS
        boundary = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        note = f" [permissions boundary: {boundary.split('/')[-1]}; effective access may be lower]" \
            if boundary else ""

        for p in inline:
            for status, reason in permission_issues(p["PolicyDocument"]):
                perm_findings.append(Finding(status, "IAM-1", f"{kind}/{name}",
                                             f"Inline policy {p['PolicyName']}: {reason}{note}", "1.16"))
        for p in entity.get("AttachedManagedPolicies", []):
            if p["PolicyArn"] in BROAD_AWS_MANAGED:
                perm_findings.append(Finding(BROAD_AWS_MANAGED[p["PolicyArn"]], "IAM-2", f"{kind}/{name}",
                                             f"AWS managed policy {p['PolicyName']} attached{note}", "1.16"))
        if role:
            for status, reason in trust_issues(role["AssumeRolePolicyDocument"], account):
                trust_findings.append(Finding(status, "IAM-3", f"role/{name}", reason))

    checked = f"{len(details['Policies'])} customer managed policies, " \
              f"{len(principals)} users/groups/roles"
    yield from perm_findings or [Finding(PASS, "IAM-1", "account", f"No overly broad policies ({checked})", "1.16")]
    yield from trust_findings or [Finding(PASS, "IAM-3", "account", "No role trusts \"*\" or unconditioned external accounts")]


@guarded("IAM")
def check_iam_credentials(session):
    iam = session.client("iam")

    summary = iam.get_account_summary()["SummaryMap"]
    yield Finding(FAIL if summary.get("AccountAccessKeysPresent") else PASS, "IAM-4", "root",
                  "Root account has access keys" if summary.get("AccountAccessKeysPresent")
                  else "Root account has no access keys", "1.4")
    yield Finding(PASS if summary.get("AccountMFAEnabled") else FAIL, "IAM-5", "root",
                  "Root account MFA enabled" if summary.get("AccountMFAEnabled")
                  else "Root account MFA not enabled (accept only if root credentials are "
                       "centrally removed by AWS Organizations)", "1.5")

    for _ in range(15):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    report = iam.get_credential_report()["Content"].decode()
    users = [r for r in csv.DictReader(io.StringIO(report)) if r["user"] != "<root_account>"]

    problems = []
    now = datetime.now(timezone.utc)
    for u in users:
        if u["password_enabled"] == "true" and u["mfa_active"] != "true":
            problems.append(Finding(FAIL, "IAM-6", f"user/{u['user']}", "Console password without MFA", "1.10"))
        for n in ("1", "2"):
            rotated = u[f"access_key_{n}_last_rotated"]
            if u[f"access_key_{n}_active"] == "true" and rotated not in ("N/A", ""):
                age = (now - datetime.fromisoformat(rotated.replace("Z", "+00:00"))).days
                if age > KEY_MAX_AGE_DAYS:
                    problems.append(Finding(WARN, "IAM-7", f"user/{u['user']}",
                                            f"Access key {n} is {age} days old (> {KEY_MAX_AGE_DAYS})", "1.14"))
    yield from problems or [Finding(PASS, "IAM-6", "account",
                                    f"{len(users)} IAM users; none with a console password but no MFA, "
                                    f"no access keys older than {KEY_MAX_AGE_DAYS} days")]

    try:
        pw = iam.get_account_password_policy()["PasswordPolicy"]
        length = pw.get("MinimumPasswordLength", 0)
        yield Finding(PASS if length >= 14 else WARN, "IAM-8", "account",
                      f"Password policy minimum length {length}", "1.8")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        yield Finding(WARN, "IAM-8", "account", "No account password policy set (AWS defaults apply)", "1.8")


# ---------------------------------------------------------------- EC2

def open_to_world(perm):
    v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
    return [c for c, hit in (("0.0.0.0/0", v4), ("::/0", v6)) if hit]


@guarded("EC2")
def check_security_groups(session, region):
    ec2 = session.client("ec2", region_name=region)
    groups = [g for page in ec2.get_paginator("describe_security_groups").paginate()
              for g in page["SecurityGroups"]]
    findings = []
    for g in groups:
        label = f"{g['GroupId']} ({g['GroupName']})"
        for perm in g.get("IpPermissions", []):
            cidrs = open_to_world(perm)
            if not cidrs:
                continue
            proto = perm.get("IpProtocol")
            if proto == "-1":
                exposed = "all traffic"
            elif proto in ("tcp", "6"):
                lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                hits = [f"{ADMIN_PORTS[p]} ({p})" for p in ADMIN_PORTS if lo <= p <= hi]
                if not hits:
                    continue
                exposed = ", ".join(hits)
            else:
                continue
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [g["GroupId"]]}])["NetworkInterfaces"]
            attached = f"attached to {len(enis)} network interface(s)" if enis else "not attached to anything"
            findings.append(Finding(FAIL, "EC2-1", label,
                                    f"Ingress {exposed} from {', '.join(cidrs)}; {attached}",
                                    "5.2" if "0.0.0.0/0" in cidrs else "5.3"))
    yield from findings or [Finding(PASS, "EC2-1", "-",
                                    f"{len(groups)} security groups: none open to the internet on admin ports")]


# ---------------------------------------------------------------- report

COLORS = {PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m", ERROR: "\033[35m"}
SECTIONS = [("CT", "CloudTrail"), ("S3", "S3"), ("IAM", "IAM"), ("EC2", "EC2 security groups")]


def make_redactor(account):
    """Own account -> 111122223333; each other account -> its own stable placeholder."""
    placeholders = {account: "111122223333"}

    def redact(text):
        def sub(m):
            if m.group() not in placeholders:
                n = len(placeholders) + 1  # 2 -> 222233334444, 3 -> 333344445555, ...
                placeholders[m.group()] = "".join(str((n + i // 4 - 1) % 9 + 1) * 4 for i in (0, 4, 8))
            return placeholders[m.group()]
        return re.sub(r"\b\d{12}\b", sub, text)
    return redact


def print_report(findings, account, region, color):
    print(f"AWS security audit  account {account}  region {region}  "
          f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC")
    width = max(len(f.resource) for f in findings)
    for prefix, title in SECTIONS:
        rows = [f for f in findings if f.check.split("-")[0] == prefix]
        if not rows:
            continue
        print(f"\n{title}")
        for f in rows:
            tag = f"[{f.status}]".ljust(7)
            if color:
                tag = f"{COLORS[f.status]}{tag}\033[0m"
            cis = f"  (CIS {f.cis})" if f.cis else ""
            print(f"  {tag} {f.check:<6} {f.resource:<{width}}  {f.detail}{cis}")

    counts = {s: sum(f.status == s for f in findings) for s in (PASS, FAIL, WARN, ERROR)}
    print("\nSummary: " + "  ".join(f"{k} {v}" for k, v in counts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--profile")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--redact", action="store_true", help="replace 12-digit account IDs in the output")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]

    findings = (check_cloudtrail(session, args.region)
                + check_s3_account(session, account)
                + check_s3_buckets(session, args.region)
                + check_iam_policies(session, account)
                + check_iam_credentials(session)
                + check_security_groups(session, args.region))

    if args.redact:
        redact = make_redactor(account)
        account = redact(account)
        for f in findings:
            f.resource, f.detail = redact(f.resource), redact(f.detail)

    if args.json:
        print(json.dumps({"account": account, "region": args.region,
                          "generated": datetime.now(timezone.utc).isoformat(),
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print_report(findings, account, args.region, color=sys.stdout.isatty() and not args.no_color)

    statuses = {f.status for f in findings}
    sys.exit(1 if FAIL in statuses else 2 if ERROR in statuses else 0)


if __name__ == "__main__":
    main()
