"""Auto-remediation: close security group rules that open admin ports to the internet.

Trigger: EventBridge rule on the CloudTrail event AuthorizeSecurityGroupIngress.
Action:  revoke any ingress rule that exposes SSH (22) or RDP (3389) to
         0.0.0.0/0 or ::/0, then email the SOC topic with what was removed.

Only the risky ranges are revoked. Other rules on the same group, and the same
ports opened to specific IP addresses, are left alone.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ADMIN_PORTS = {22, 3389}
WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"


def _covers_admin_port(permission):
    """True when the rule's port range includes SSH or RDP (or all traffic)."""
    if permission.get("IpProtocol") == "-1":
        return True
    if permission.get("IpProtocol") not in ("tcp", "6"):
        return False
    low = permission.get("FromPort")
    high = permission.get("ToPort")
    if low is None or high is None:
        return False
    return any(low <= port <= high for port in ADMIN_PORTS)


def find_risky_permissions(security_group):
    """Return the ingress permissions that should be revoked, trimmed to the world-open ranges only."""
    risky = []
    for permission in security_group.get("IpPermissions", []):
        if not _covers_admin_port(permission):
            continue
        v4 = [r for r in permission.get("IpRanges", []) if r.get("CidrIp") == WORLD_V4]
        v6 = [r for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == WORLD_V6]
        if not v4 and not v6:
            continue
        trimmed = {"IpProtocol": permission["IpProtocol"]}
        if "FromPort" in permission:
            trimmed["FromPort"] = permission["FromPort"]
            trimmed["ToPort"] = permission["ToPort"]
        if v4:
            trimmed["IpRanges"] = [{"CidrIp": WORLD_V4}]
        if v6:
            trimmed["Ipv6Ranges"] = [{"CidrIpv6": WORLD_V6}]
        risky.append(trimmed)
    return risky


def _describe(permission):
    ports = "all ports" if permission["IpProtocol"] == "-1" else f"port {permission['FromPort']}-{permission['ToPort']}"
    ranges = [r["CidrIp"] for r in permission.get("IpRanges", [])] + [
        r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])
    ]
    return f"{permission['IpProtocol']} {ports} from {', '.join(ranges)}"


def handler(event, context, ec2=None, sns=None):
    ec2 = ec2 or boto3.client("ec2")
    sns = sns or boto3.client("sns")

    detail = event.get("detail", {})
    group_id = detail.get("requestParameters", {}).get("groupId")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    if not group_id:
        logger.info("No groupId in event; nothing to do: %s", json.dumps(detail)[:500])
        return {"remediated": False, "reason": "no groupId"}

    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    if not groups:
        return {"remediated": False, "reason": "group not found"}

    risky = find_risky_permissions(groups[0])
    if not risky:
        logger.info("%s has no world-open admin ports", group_id)
        return {"remediated": False, "group_id": group_id}

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=risky)
    removed = [_describe(p) for p in risky]
    logger.info("Revoked on %s: %s", group_id, removed)

    message = (
        "AUTO-REMEDIATION: security group rule closed\n\n"
        f"Group:   {group_id}\n"
        f"Opened by: {actor}\n"
        f"Removed: {'; '.join(removed)}\n\n"
        "MITRE ATT&CK T1562.007 (Disable or Modify Cloud Firewall).\n"
        "Next step: confirm with the owner whether this was intended. If remote "
        "access is needed, allow a specific IP address or use Session Manager."
    )
    sns.publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=f"[AUTO-FIX] Closed world-open admin port on {group_id}"[:100],
        Message=message,
    )
    return {"remediated": True, "group_id": group_id, "removed": removed}
