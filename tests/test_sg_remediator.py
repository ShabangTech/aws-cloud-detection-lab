"""Unit tests for the auto-remediation Lambda. No AWS account needed: the EC2
and SNS clients are replaced with simple fakes."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
os.environ.setdefault("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:test")

import sg_remediator as r


class FakeEC2:
    def __init__(self, permissions):
        self.group = {"GroupId": "sg-123", "IpPermissions": permissions}
        self.revoked = None

    def describe_security_groups(self, GroupIds):
        return {"SecurityGroups": [self.group]}

    def revoke_security_group_ingress(self, GroupId, IpPermissions):
        self.revoked = IpPermissions


class FakeSNS:
    def __init__(self):
        self.messages = []

    def publish(self, **kwargs):
        self.messages.append(kwargs)


def event(group_id="sg-123"):
    return {
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {"groupId": group_id},
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker"},
        }
    }


def rule(port_from, port_to, v4=(), v6=(), proto="tcp"):
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in v4], "Ipv6Ranges": [{"CidrIpv6": c} for c in v6]}
    if proto != "-1":
        p["FromPort"], p["ToPort"] = port_from, port_to
    return p


def run(permissions):
    ec2, sns = FakeEC2(permissions), FakeSNS()
    result = r.handler(event(), None, ec2=ec2, sns=sns)
    return result, ec2, sns


def test_ssh_open_to_world_is_revoked_and_alerted():
    result, ec2, sns = run([rule(22, 22, v4=["0.0.0.0/0"])])
    assert result["remediated"] is True
    assert ec2.revoked == [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    assert "sg-123" in sns.messages[0]["Subject"]


def test_rdp_open_to_ipv6_world_is_revoked():
    result, ec2, _ = run([rule(3389, 3389, v6=["::/0"])])
    assert result["remediated"] is True
    assert ec2.revoked[0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_port_range_covering_ssh_is_revoked():
    result, _, _ = run([rule(0, 1024, v4=["0.0.0.0/0"])])
    assert result["remediated"] is True


def test_all_traffic_rule_is_revoked():
    result, ec2, _ = run([rule(None, None, v4=["0.0.0.0/0"], proto="-1")])
    assert result["remediated"] is True
    assert "FromPort" not in ec2.revoked[0]


def test_only_world_range_is_removed_from_mixed_rule():
    _, ec2, _ = run([rule(22, 22, v4=["0.0.0.0/0", "203.0.113.10/32"])])
    assert ec2.revoked[0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]


def test_https_open_to_world_is_left_alone():
    result, ec2, sns = run([rule(443, 443, v4=["0.0.0.0/0"])])
    assert result["remediated"] is False
    assert ec2.revoked is None and sns.messages == []


def test_ssh_from_single_ip_is_left_alone():
    result, ec2, _ = run([rule(22, 22, v4=["203.0.113.10/32"])])
    assert result["remediated"] is False
    assert ec2.revoked is None


def test_udp_on_port_22_is_left_alone():
    result, _, _ = run([rule(22, 22, v4=["0.0.0.0/0"], proto="udp")])
    assert result["remediated"] is False


def test_event_without_group_id_is_ignored():
    ec2, sns = FakeEC2([]), FakeSNS()
    result = r.handler({"detail": {"requestParameters": {}}}, None, ec2=ec2, sns=sns)
    assert result == {"remediated": False, "reason": "no groupId"}
