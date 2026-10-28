# Detections

Each detection is a CloudWatch Logs metric filter on the CloudTrail log group,
paired with an alarm that emails the SOC topic. Every one maps to a MITRE
ATT&CK technique. Severity is a triage hint, not a formal risk score.

## Scope: why two detections stay quiet on a projects account

CloudTrail splits events into **regional** and **global**. Since November 2021,
AWS delivers global service events (IAM, STS, CloudFront) only to a
**multi-Region trail**, or to a single-Region trail in **us-east-1**. The
landing zone runs a single-Region trail in us-east-2, so IAM events never reach
it, and the two global detections below have nothing to match.

That is a real-world lesson, not a bug: a single-Region trail outside us-east-1
is blind to identity changes. On a standard account you set `multi_region = true`
on the landing zone's audit-trail module and all nine light up. The detections
are written and deployed either way, so the gap is visible and documented rather
than hidden.

| ID | Detection | Severity | MITRE | Scope |
|----|-----------|----------|-------|-------|
| D01 | Logging or detection tampering | CRITICAL | T1562.008 | regional |
| D02 | Security group opened to the internet | HIGH | T1562.007 | regional |
| D03 | S3 exposure controls changed | HIGH | T1530 | regional |
| D04 | KMS key disabled or scheduled for deletion | HIGH | T1485 | regional |
| D05 | Burst of denied API calls | MEDIUM | T1580 | regional |
| D06 | EC2 SSH key pair created or imported | MEDIUM | T1098.004 | regional |
| D07 | Secret values read with decryption | MEDIUM | T1555.006 | regional |
| D08 | New IAM user, password or access key | HIGH | T1098.001 / T1136.003 | global |
| D09 | AdministratorAccess granted | CRITICAL | T1098.003 | global |

## How each detection reads

- **D01** watches the control plane for anyone turning off visibility:
  `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, `DeleteLogGroup`, and the
  alarm-deletion calls. Disabling logging is usually the first move after a
  compromise, so this is the highest-value rule in the set.
- **D02** matches `AuthorizeSecurityGroupIngress` where the added range is
  `0.0.0.0/0` or `::/0`. It fires alongside the auto-remediation (see
  REMEDIATION.md), so you see the alert and the fix together.
- **D03** flags changes to the things that keep a bucket private: bucket
  policy, ACL, and the account or bucket public-access block.
- **D04** catches `DisableKey` and `ScheduleKeyDeletion`. Destroying a KMS key
  makes everything it encrypted unreadable, so this is a destruction signal.
- **D05** counts `AccessDenied` and `UnauthorizedOperation` errors and alarms
  at five in five minutes. One denial is noise; a burst is enumeration.
- **D06** flags new EC2 key pairs, a common persistence step for keeping access
  to instances.
- **D07** flags reads of decrypted secrets (SSM `GetParameter(s)` with
  `withDecryption = true`, and Secrets Manager `GetSecretValue`).
- **D08 / D09** cover identity persistence and privilege escalation. They need
  a multi-Region trail to see anything (above).

## Tuning notes

- **Thresholds:** every rule except D05 alarms on a single occurrence, which
  suits a lab. In production you would raise thresholds and add known-good
  identities (CI/CD roles, Terraform) to a suppression list so routine
  automation doesn't page anyone.
- **Period:** alarms use a 5-minute period, so expect a 5 to 15 minute delay
  end to end (CloudTrail to CloudWatch delivery plus the alarm window).
- **Cost:** nine metrics and nine alarms sit inside the CloudWatch free tier
  (10 custom metrics, 10 alarms). Logs Insights charges only for data scanned
  when you run a saved query, fractions of a cent at lab volume.

## Validating a detection (defensive self-test)

A detection you have never seen fire is a detection you don't trust. Validate
each one against your **own** throwaway resources, during a change window, and
undo it straight after. This is standard detection engineering, the same thing
a SOC does when it onboards a new rule.

A safe validation touches only resources you created for the test, never
anything in use, and never makes data public (the landing zone's account-wide
S3 Block Public Access stays on throughout). For example:

- **D01** — stop your own trail's logging, confirm the alert, then turn logging
  back on immediately and verify `IsLogging` is `true` again.
- **D04** — create a brand-new KMS key with no data under it, schedule it for
  deletion with the longest window (so you can cancel), confirm the alert, then
  cancel the deletion.
- **D05** — call a few APIs your role is not allowed to use and watch the
  denied-call burst alarm.

For each test, record: what you did, which alarm fired, how long it took, and
the Logs Insights query that showed the activity. That evidence table (see
WALKTHROUGH.md) is the most interview-ready part of the whole project, because
it proves the pipeline works end to end.

Full MITRE technique pages: https://attack.mitre.org/techniques/enterprise/
