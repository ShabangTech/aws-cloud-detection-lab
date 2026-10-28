# Walkthrough

How to stand the lab up, prove it works, and collect the evidence that makes it
a portfolio piece. Fill in the blanks as you go.

## Part 1: Turn on the log stream

The detections read from CloudWatch Logs, so the landing-zone trail has to
deliver there first.

```bash
cd ../aws-hipaa-landing-zone/envs/dev
terraform apply -var="cloudtrail_to_cloudwatch=true"
terraform output cloudtrail_log_group_name      # e.g. /hlz/cloudtrail
```

This adds 3 resources: a KMS-encrypted log group, a role CloudTrail assumes to
write to it, and that role's policy.

## Part 2: Deploy the lab

```bash
cd ../../aws-cloud-detection-lab
cp backend.hcl.example backend.hcl               # same state bucket as the landing zone
cp terraform.tfvars.example terraform.tfvars     # set alert_email + the log group name
$env:AWS_PROFILE = "hlz"

terraform init "-backend-config=backend.hcl"
terraform plan  "-out=lab.tfplan"
terraform apply "lab.tfplan"
```

Confirm the SNS email ("AWS Notification - Subscription Confirmation"). No
alerts arrive until you click the link.

Record the outputs:

| Output | Value |
|--------|-------|
| alert_topic_arn | |
| auto_remediation_function | |
| detections (count) | 9 |

## Part 3: Validate the detections

For each regional detection, run a safe self-test against your own throwaway
resources during a change window and undo it immediately
([how](DETECTIONS.md#validating-a-detection-defensive-self-test)). Record the
evidence:

| ID | Self-test action | Alarm fired? | Time to alert | Hunting query used |
|----|------------------|--------------|---------------|--------------------|
| D01 | | | | defense-evasion |
| D02 | | | | defense-evasion |
| D03 | | | | triage-recent-activity |
| D04 | | | | defense-evasion |
| D05 | | | | denied-calls-by-identity |
| D06 | | | | triage-recent-activity |
| D07 | | | | triage-recent-activity |
| D08 | n/a on this account | no (global) | — | new-credentials-and-users |
| D09 | n/a on this account | no (global) | — | new-credentials-and-users |

D08 and D09 are expected to stay quiet here. Note *why* in your write-up (the
single-Region IAM gap) — explaining a non-fire correctly reads as more
competent than pretending everything lit up.

## Part 4: Watch the auto-fix

On a throwaway security group not attached to anything, add an inbound SSH rule
from `0.0.0.0/0`, then watch:

- The rule disappears within seconds (refresh the group's inbound rules).
- An email arrives: "[AUTO-FIX] Closed world-open admin port on sg-…".
- D02's alarm also fires.
- The function log at `/aws/lambda/cdl-sg-remediator` shows what it revoked.

Capture the before/after and delete the group.

| Evidence | Captured? |
|----------|-----------|
| Inbound rule before | |
| Inbound rule after (gone) | |
| Auto-fix email | |
| Lambda log line | |

## Part 5: Tear down

```bash
terraform destroy
```

Optionally set `cloudtrail_to_cloudwatch=false` on the landing zone afterward.

## Lessons learned

Three or four sentences, in your own words: what the single-Region IAM gap
taught you, why detection plus response beats either alone, and one thing you
would change for production (thresholds, suppression lists, a dashboard).
