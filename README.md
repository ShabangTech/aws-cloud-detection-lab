# AWS Cloud Detection Lab

A detection-and-response layer for the
[aws-hipaa-landing-zone](https://github.com/ShabangTech/aws-hipaa-landing-zone).
The landing zone collects the logs; this repo turns them into **detections,
alerts, threat-hunting queries, and an automatic fix** for one common
misconfiguration.

Everything is Terraform and a small Python Lambda. It runs at **$0** on an AWS
free-plan "projects" account and stays inside the CloudWatch free tier.

## What it deploys

- **9 detections** as CloudWatch metric filters + alarms, each mapped to a
  [MITRE ATT&CK](https://attack.mitre.org/) technique — logging tampering,
  world-open security groups, S3 exposure, KMS destruction, denied-call bursts,
  new SSH keys, secret reads, and (on a multi-Region trail) IAM persistence and
  privilege escalation. See [docs/DETECTIONS.md](docs/DETECTIONS.md).
- **Email alerts** through one SNS topic every alarm publishes to.
- **5 saved Logs Insights queries** for triage and threat hunting.
- **Auto-remediation:** an EventBridge rule and Lambda that close SSH/RDP rules
  opened to the internet, then report what they removed. See
  [docs/REMEDIATION.md](docs/REMEDIATION.md).

## Architecture

```
          AWS API calls
                |
          CloudTrail  ──►  S3 log archive (landing zone, encrypted, validated)
                |
                └──►  CloudWatch Logs  ──►  metric filters  ──►  alarms ──► SNS ──► email
                               |                                               ▲
                               └──►  Logs Insights (saved hunting queries)     |
                                                                               |
          EventBridge (AuthorizeSecurityGroupIngress)  ──►  Lambda  ──►  revoke rule + alert
```

## Prerequisites

1. The landing zone deployed, with the trail streaming to CloudWatch:
   ```bash
   # in aws-hipaa-landing-zone/envs/dev
   terraform apply -var="cloudtrail_to_cloudwatch=true"
   terraform output cloudtrail_log_group_name   # e.g. /hlz/cloudtrail
   ```
2. Terraform, AWS CLI v2.32+, and `aws login` with the `hlz` profile (same
   setup as the landing zone).

## Deploy

```bash
cp backend.hcl.example backend.hcl            # same state bucket as the landing zone
cp terraform.tfvars.example terraform.tfvars  # set alert_email + the log group name
$env:AWS_PROFILE = "hlz"

terraform init "-backend-config=backend.hcl"
terraform plan  "-out=lab.tfplan"
terraform apply "lab.tfplan"
```

Then **confirm the SNS subscription**: AWS emails `alert_email` a confirmation
link, and no alerts arrive until you click it.

## Results

First live run: a world-open SSH rule was **closed automatically in 7 to 9
seconds**, the D02 alarm emailed in about 2 minutes, and CloudTrail shows the
full attack-and-response timeline. Screenshots, timings and lessons learned:
[docs/RESULTS.md](docs/RESULTS.md).

## Try it

Validate the detections against your own throwaway resources, during a change
window, and undo each test right after — the defensive self-test described in
[docs/DETECTIONS.md](docs/DETECTIONS.md#validating-a-detection-defensive-self-test).
Record which alarm fired and how long it took; that evidence table is the
portfolio centerpiece.

## Tear down

```bash
terraform destroy
```

Costs stay at $0 if you keep it up only while working. Nothing here leaves the
free tier, but tearing down between sessions is the tidy habit.

## Layout

```
detections.tf    9 metric filters + alarms (local.detections)
alerts.tf        SNS topic, policy, email subscription
hunting.tf       5 saved Logs Insights queries
remediation.tf   EventBridge rule, Lambda, least-privilege role
lambda/          sg_remediator.py
tests/           pytest unit tests (no AWS account needed)
docs/            DETECTIONS.md, REMEDIATION.md, WALKTHROUGH.md, ROADMAP.md
```

## Safety

This repo is defensive. It reads logs and closes risky rules; it contains no
offensive tooling. Validation touches only resources you create for a test and
never makes data public. Never commit `backend.hcl` or `terraform.tfvars`
(both git-ignored), and never paste credentials into code or commits.
