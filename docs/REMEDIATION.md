# Auto-remediation

## What it does

When someone adds a security group rule that opens **SSH (22)** or **RDP
(3389)** to the whole internet (`0.0.0.0/0` or `::/0`), the lab closes that rule
within seconds and emails the SOC topic explaining what it removed.

```
AuthorizeSecurityGroupIngress  ->  CloudTrail  ->  EventBridge rule
      ->  Lambda (sg_remediator.py)  ->  RevokeSecurityGroupIngress + SNS alert
```

Detection D02 still fires in parallel, so the analyst gets both the alert and
the fix. Detection without response tells you that you were exposed; response
without detection hides that it happened. You want both.

## Design choices worth explaining in an interview

- **Surgical, not blunt.** The Lambda revokes only the world-open ranges on the
  admin ports. Other rules on the same group, and the same port opened to a
  specific office IP, are left untouched. It reads the group's live rules,
  keeps only the `0.0.0.0/0` and `::/0` ranges that cover 22 or 3389, and
  revokes exactly those. See `find_risky_permissions` in
  `lambda/sg_remediator.py`.
- **Least privilege.** The function's role can do four things: describe
  security groups, revoke ingress in this account and region, publish the one
  SNS topic, and write its own logs. Nothing else.
- **Handles the edge cases.** A rule with `IpProtocol = -1` (all traffic)
  counts as covering the admin ports. A range that spans the port (for example
  0 to 1024) counts too. UDP on 22 does not. These are the cases in the unit
  tests.
- **Idempotent and safe to re-run.** If the rule is already gone, the function
  reports `remediated: false` and does nothing.

## Tests

`tests/test_sg_remediator.py` runs with no AWS account. The EC2 and SNS clients
are replaced with fakes, so the tests assert exactly which ranges get revoked
and when an alert is sent. Nine cases cover SSH, RDP, IPv6, port ranges,
all-traffic rules, mixed rules (only the world range removed), and the
left-alone cases (HTTPS open, SSH from a single IP, UDP, missing group ID).

```bash
python3 -m pytest -q tests
```

## Turning it off

Set `enable_auto_remediation = false`. The detections and alerts stay; only the
EventBridge rule and Lambda are removed. Some teams prefer alert-only until they
trust a rule in production, which is itself a good talking point.
