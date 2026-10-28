# Glossary

Every acronym used in this lab and in the
[aws-hipaa-landing-zone](https://github.com/ShabangTech/aws-hipaa-landing-zone).

## Names on the resources

| Acronym | Means |
|---------|-------|
| cdl | Cloud Detection Lab, the prefix on everything this repo creates (`cdl-sg-remediator`, `cdl-security-alerts`) |
| hlz | HIPAA Landing Zone, the prefix on everything the landing zone creates (`hlz-trail`, `/hlz/cloudtrail`) |
| sg | Security Group, AWS's virtual firewall (`cdl-sg-remediator` = the lab's security group fixer) |
| D01 to D09 | Detection 1 to 9 (see [DETECTIONS.md](DETECTIONS.md)) |

## AWS services

| Acronym | Means |
|---------|-------|
| AWS | Amazon Web Services |
| IAM | Identity and Access Management: users, roles and permissions |
| STS | Security Token Service, which issues temporary credentials |
| SNS | Simple Notification Service, which sends the alert emails |
| S3 | Simple Storage Service, where the logs are archived |
| KMS | Key Management Service, which holds the encryption keys |
| VPC | Virtual Private Cloud, the private network |
| EC2 | Elastic Compute Cloud: servers, and where security groups live |
| SCP | Service Control Policy, an organization-wide guardrail that can deny API calls |
| ARN | Amazon Resource Name, the unique ID of any AWS resource |
| CLI | Command Line Interface (the `aws` command) |
| OIDC | OpenID Connect, which lets GitHub Actions sign in to AWS without stored keys |

## Security terms

| Acronym | Means |
|---------|-------|
| MITRE ATT&CK | MITRE's catalog of Adversarial Tactics, Techniques & Common Knowledge; each T-number (like T1562.007) is one technique |
| SOC | Security Operations Center |
| SIEM | Security Information and Event Management (for example, Splunk) |
| HIPAA | Health Insurance Portability and Accountability Act |
| PHI | Protected Health Information |
| MFA | Multi-Factor Authentication |
| SSH | Secure Shell, remote login on port 22 |
| RDP | Remote Desktop Protocol, port 3389 |
| CIDR | Classless Inter-Domain Routing, notation for IP ranges; `0.0.0.0/0` means the entire internet |
| OSINT | Open-Source Intelligence |

## Tools and practices

| Acronym | Means |
|---------|-------|
| IaC | Infrastructure as Code, which is what Terraform does |
| CI/CD | Continuous Integration / Continuous Delivery (the GitHub Actions checks) |
