"""Review recent CloudTrail events for risky actions.

Uses CloudTrail LookupEvents (90-day management event history; free; works
without a trail). Two passes per region:
  1. targeted lookups for each risky event name (complete coverage), and
  2. a capped scan of all events, for root activity and repeated AccessDenied
     errors, which LookupEvents cannot filter on.
IAM, STS and console sign-in events are recorded in us-east-1, so that region
is always included alongside --region.

Exit code: 1 if any HIGH finding, else 0.
"""

import argparse
import json
import sys
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from audit import make_redactor

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}
ACCESS_DENIED_THRESHOLD = 5
WORLD = {"0.0.0.0/0", "::/0"}
ADMIN_POLICIES = ("AdministratorAccess", "IAMFullAccess")

# event name -> (base severity, category). Analysers below can raise severity.
RISKY_EVENTS = {
    # Defense evasion: blinding the audit trail or weakening controls
    "StopLogging": (HIGH, "defense evasion"),
    "DeleteTrail": (HIGH, "defense evasion"),
    "UpdateTrail": (MEDIUM, "defense evasion"),
    "PutEventSelectors": (MEDIUM, "defense evasion"),
    "DeleteFlowLogs": (HIGH, "defense evasion"),
    "DisableKey": (HIGH, "defense evasion"),
    "ScheduleKeyDeletion": (HIGH, "defense evasion"),
    "DisableKeyRotation": (MEDIUM, "defense evasion"),
    "DeletePublicAccessBlock": (HIGH, "data exposure"),
    "DeleteAccountPublicAccessBlock": (HIGH, "data exposure"),
    "PutPublicAccessBlock": (LOW, "data exposure"),
    "PutAccountPublicAccessBlock": (LOW, "data exposure"),
    # Data / network exposure
    "PutBucketPolicy": (MEDIUM, "data exposure"),
    "PutBucketAcl": (MEDIUM, "data exposure"),
    "AuthorizeSecurityGroupIngress": (LOW, "network exposure"),
    # Privilege escalation and persistence
    "CreateUser": (MEDIUM, "persistence"),
    "CreateLoginProfile": (MEDIUM, "persistence"),
    "CreateAccessKey": (HIGH, "persistence"),
    "AttachUserPolicy": (MEDIUM, "privilege escalation"),
    "AttachRolePolicy": (MEDIUM, "privilege escalation"),
    "AttachGroupPolicy": (MEDIUM, "privilege escalation"),
    "PutUserPolicy": (MEDIUM, "privilege escalation"),
    "PutRolePolicy": (MEDIUM, "privilege escalation"),
    "PutGroupPolicy": (MEDIUM, "privilege escalation"),
    "CreatePolicyVersion": (MEDIUM, "privilege escalation"),
    "UpdateAssumeRolePolicy": (MEDIUM, "privilege escalation"),
    "DeleteRolePermissionsBoundary": (HIGH, "privilege escalation"),
    "DeleteUserPermissionsBoundary": (HIGH, "privilege escalation"),
    "CreatePolicy": (LOW, "privilege escalation"),
    "CreateRole": (LOW, "persistence"),
    # Identity
    "ConsoleLogin": (LOW, "identity"),
}


@dataclass
class Finding:
    time: str
    severity: str
    category: str
    event: str
    principal: str
    source_ip: str
    region: str
    detail: str
    event_id: str = ""


# ---------------------------------------------------------------- helpers

def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy(doc):
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except json.JSONDecodeError:
            return {}
    return doc or {}


def is_star_star(policy):
    for st in as_list(policy.get("Statement")):
        if st.get("Effect") == "Allow" and "*" in as_list(st.get("Action")) \
                and "*" in as_list(st.get("Resource")):
            return True
    return False


def principal_of(ev):
    ui = ev.get("userIdentity", {})
    kind = ui.get("type")
    if kind == "Root":
        return "root"
    if kind == "AssumedRole":
        role, _, session = ui.get("arn", "").split(":assumed-role/")[-1].partition("/")
        return f"role/{role}/{session[:8]}" if session else f"role/{role}"
    if kind == "IAMUser":
        return f"user/{ui.get('userName', '?')}"
    if kind == "AWSService":
        return ui.get("invokedBy", "aws-service")
    return ui.get("arn") or kind or "?"


# ---------------------------------------------------------------- analysers

def analyse(ev):
    """Return (severity, detail) for a risky event, refined by its request parameters."""
    name = ev["eventName"]
    severity, _ = RISKY_EVENTS[name]
    req = ev.get("requestParameters") or {}
    detail = ""

    if name == "AuthorizeSecurityGroupIngress":
        exposures = []
        for perm in req.get("ipPermissions", {}).get("items", []):
            cidrs = [r.get("cidrIp") for r in perm.get("ipRanges", {}).get("items", [])] + \
                    [r.get("cidrIpv6") for r in perm.get("ipv6Ranges", {}).get("items", [])]
            world = [c for c in cidrs if c in WORLD]
            if not world:
                continue
            proto, lo, hi = perm.get("ipProtocol"), perm.get("fromPort"), perm.get("toPort")
            ports = "all traffic" if proto == "-1" else f"{proto}/{lo}" + (f"-{hi}" if hi != lo else "")
            exposures.append(f"{ports} from {', '.join(world)}")
            admin = proto == "-1" or (lo is not None and any(lo <= p <= hi for p in (22, 3389)))
            if admin:
                severity = HIGH
            elif severity != HIGH:
                severity = MEDIUM
        detail = f"{req.get('groupId', '?')}: " + ("; ".join(exposures) if exposures else "no internet-wide rule")

    elif name in ("PutRolePolicy", "PutUserPolicy", "PutGroupPolicy"):
        target = req.get("roleName") or req.get("userName") or req.get("groupName")
        star = is_star_star(parse_policy(req.get("policyDocument")))
        if star:
            severity = HIGH
        detail = f"{target}: inline policy {req.get('policyName')}" + (' grants "*" on "*"' if star else "")

    elif name in ("AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy"):
        target = req.get("roleName") or req.get("userName") or req.get("groupName")
        arn = req.get("policyArn", "")
        if arn.split("/")[-1] in ADMIN_POLICIES:
            severity = HIGH
        detail = f"{target}: attached {arn.split('/')[-1]}"

    elif name == "CreatePolicyVersion":
        star = is_star_star(parse_policy(req.get("policyDocument")))
        if star and req.get("setAsDefault"):
            severity = HIGH
        detail = f"{req.get('policyArn', '').split('/')[-1]}: setAsDefault={req.get('setAsDefault')}" \
                 + (' grants "*" on "*"' if star else "")

    elif name == "CreatePolicy":
        star = is_star_star(parse_policy(req.get("policyDocument")))
        detail = req.get("policyName", "")
        if star:
            severity, detail = HIGH, detail + ' grants "*" on "*"'

    elif name == "PutBucketPolicy":
        policy = parse_policy(req.get("bucketPolicy"))
        public = any(st.get("Effect") == "Allow" and st.get("Principal") in ("*", {"AWS": "*"})
                     for st in as_list(policy.get("Statement")))
        if public:
            severity = HIGH
        detail = f"{req.get('bucketName')}" + (": Allow to Principal \"*\"" if public else "")

    elif name in ("PutPublicAccessBlock", "PutAccountPublicAccessBlock"):
        config = req.get("PublicAccessBlockConfiguration", {})
        off = [k for k, v in config.items() if v is False]
        if off:
            severity = HIGH
        target = req.get("bucketName") or "account"
        detail = f"{target}: " + (f"turned OFF {', '.join(off)}" if off else "all settings on")

    elif name == "UpdateAssumeRolePolicy":
        policy = parse_policy(req.get("policyDocument"))
        anyone = any(st.get("Principal") in ("*", {"AWS": "*"}) for st in as_list(policy.get("Statement")))
        if anyone:
            severity = HIGH
        detail = f"{req.get('roleName')}" + (': trust policy allows Principal "*"' if anyone else "")

    elif name == "ConsoleLogin":
        outcome = (ev.get("responseElements") or {}).get("ConsoleLogin")
        mfa = (ev.get("additionalEventData") or {}).get("MFAUsed")
        if outcome == "Failure":
            severity, detail = MEDIUM, "Failed console sign-in"
        elif mfa != "Yes" and ev.get("userIdentity", {}).get("type") in ("Root", "IAMUser"):
            severity, detail = HIGH, "Console sign-in without MFA"
        else:
            detail = f"Console sign-in ({'MFA' if mfa == 'Yes' else 'federated/SSO'})"

    else:
        target = req.get("name") or req.get("trailName") or req.get("userName") or \
                 req.get("roleName") or req.get("bucketName") or req.get("keyId") or ""
        detail = str(target)

    if ev.get("errorCode"):
        detail += f" [FAILED: {ev['errorCode']}]"
    return severity, detail


# ---------------------------------------------------------------- collection

def lookup(ct, start, end, attribute=None, limit=None):
    kwargs = {"StartTime": start, "EndTime": end}
    if attribute:
        kwargs["LookupAttributes"] = [attribute]
    count = 0
    for page in ct.get_paginator("lookup_events").paginate(**kwargs):
        for e in page["Events"]:
            yield json.loads(e["CloudTrailEvent"])
            count += 1
            if limit and count >= limit:
                return


def review_region(session, region, start, end, max_scan):
    ct = session.client("cloudtrail", region_name=region,
                        config=Config(retries={"max_attempts": 10, "mode": "adaptive"}))
    findings, seen = [], set()

    def add(ev, severity, category, detail):
        if ev["eventID"] in seen:
            return
        seen.add(ev["eventID"])
        findings.append(Finding(ev["eventTime"], severity, category, ev["eventName"], principal_of(ev),
                                ev.get("sourceIPAddress", "?"), region, detail, ev["eventID"]))

    # Pass 1: targeted lookups by event name.
    for name, (_, category) in RISKY_EVENTS.items():
        for ev in lookup(ct, start, end, {"AttributeKey": "EventName", "AttributeValue": name}):
            if ev.get("userIdentity", {}).get("type") == "Root":
                continue  # reported in pass 2 with the root finding
            severity, detail = analyse(ev)
            add(ev, severity, category, detail)

    # Pass 2: capped scan of all events for root activity and AccessDenied patterns.
    denied = defaultdict(Counter)
    scanned, truncated = 0, False
    for ev in lookup(ct, start, end, limit=max_scan):
        scanned += 1
        if ev.get("userIdentity", {}).get("type") == "Root":
            detail = "Root account activity"
            if ev["eventName"] in RISKY_EVENTS:
                detail += " | " + analyse(ev)[1]
            add(ev, HIGH, "identity", detail)
        if ev.get("errorCode") in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                                   "Client.UnauthorizedOperation"):
            denied[principal_of(ev)][ev["eventName"]] += 1
    truncated = scanned >= max_scan

    for principal, events in denied.items():
        total = sum(events.values())
        top = ", ".join(f"{n} x{c}" for n, c in events.most_common(4))
        findings.append(Finding(end.isoformat(timespec="seconds").replace("+00:00", "Z"),
                                MEDIUM if total >= ACCESS_DENIED_THRESHOLD else LOW, "discovery",
                                "AccessDenied (aggregate)", principal, "-", region,
                                f"{total} denied calls: {top}"))
    return findings, scanned, truncated


# ---------------------------------------------------------------- report

def print_report(findings, stats, hours, regions):
    print(f"CloudTrail risky-activity review  last {hours}h  regions {', '.join(regions)}")
    for region, (scanned, truncated) in stats.items():
        note = f" (scan capped at {scanned}; raise --max-scan for full root/AccessDenied coverage)" \
            if truncated else ""
        print(f"  {region}: {scanned} events scanned for root/AccessDenied{note}")
    if not findings:
        print("\nNo risky events found.")
        return

    width = max(len(f.principal) for f in findings)
    ip_width = max(len(f.source_ip) for f in findings)
    print()
    for f in findings:
        print(f"  {f.time[:19].replace('T', ' ')}  {f.severity:<6}  {f.event:<30}  "
              f"{f.principal:<{width}}  {f.source_ip:<{ip_width}}  {f.region:<9}  {f.detail}")
    counts = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)
    print(f"\nSummary: HIGH {counts[HIGH]}  MEDIUM {counts[MEDIUM]}  LOW {counts[LOW]}   |   "
          + "  ".join(f"{c} {n}" for c, n in by_cat.most_common()))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hours", type=float, default=24, help="look-back window (max 2160 = 90 days)")
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--profile")
    parser.add_argument("--min-severity", choices=[HIGH, MEDIUM, LOW], default=LOW)
    parser.add_argument("--max-scan", type=int, default=5000,
                        help="max events per region for the root/AccessDenied scan")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--redact", action="store_true", help="replace 12-digit account IDs and source IPs")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)
    regions = list(dict.fromkeys([args.region, "us-east-1"]))

    findings, stats = [], {}
    for region in regions:
        try:
            found, scanned, truncated = review_region(session, region, start, end, args.max_scan)
        except ClientError as e:
            err = e.response["Error"]
            print(f"ERROR in {region}: {err['Code']}: {err['Message'][:160]}", file=sys.stderr)
            sys.exit(2)
        findings += found
        stats[region] = (scanned, truncated)

    cutoff = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= cutoff]
    findings.sort(key=lambda f: f.time, reverse=True)            # newest first...
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])      # ...within each severity (stable sort)

    if args.redact:
        account = session.client("sts").get_caller_identity()["Account"]
        redact = make_redactor(account)
        for f in findings:
            f.principal, f.detail = redact(f.principal), redact(f.detail)
            if f.source_ip[:1].isdigit():
                f.source_ip = "x.x.x.x"

    if args.json:
        print(json.dumps({"window_hours": args.hours, "regions": regions,
                          "scanned": {r: s for r, (s, _) in stats.items()},
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print_report(findings, stats, args.hours, regions)

    sys.exit(1 if any(f.severity == HIGH for f in findings) else 0)


if __name__ == "__main__":
    main()
