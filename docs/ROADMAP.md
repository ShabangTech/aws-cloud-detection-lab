# Roadmap

About 8 to 12 hours, roughly 1 to 2 weeks at 1 to 2 hours a day. Builds on the
landing zone and doubles as its Phase 3 (auto-remediation).

## Phase 1: Detections (3 to 4 hours)
- [x] Stream the landing-zone trail to CloudWatch Logs (feature flag)
- [x] 9 metric filters + alarms, each mapped to MITRE ATT&CK
- [x] SNS topic with email subscription
- [x] Document scope (regional vs global) and the single-Region IAM gap

## Phase 2: Response (2 to 3 hours)
- [x] EventBridge rule on AuthorizeSecurityGroupIngress
- [x] Python Lambda that revokes world-open SSH/RDP rules
- [x] Least-privilege role (describe, revoke, publish, own logs)
- [x] pytest unit tests, no AWS account needed

## Phase 3: Hunting (1 to 2 hours)
- [x] 5 saved Logs Insights queries for triage and hunting
- [ ] Run each saved query against real activity and screenshot the results

## Phase 4: Validate and document (2 to 3 hours)
- [ ] Deploy to the projects account and confirm the SNS subscription
- [ ] Validate each regional detection with a safe self-test; record the
      evidence table (action, alarm, time to alert, hunting query)
- [ ] Trigger the firewall fix on a throwaway security group; capture the
      before/after and the Lambda's alert
- [ ] Architecture diagram image for the README
- [ ] Short lessons-learned write-up
- [ ] Add a resume bullet and link the repo

## Later ideas
- [ ] Standard account: set multi_region = true and confirm D08/D09 fire
- [ ] Second responder: re-enable logging automatically if a trail is stopped
- [ ] Group detections into a CloudWatch dashboard
- [ ] Forward alerts to a chat webhook as well as email
