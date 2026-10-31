# Hunting cheat sheet: CloudTrail in CloudWatch Logs Insights

Queries for hunting through the trail's log group (`/hlz/cloudtrail`), from
basic to intermediate. Paste any of them into Logs Insights below the
`SOURCE` line, pick a time range, and click **Run**.

Each one says what it answers and what to look for. Replace the example
values (`203.0.113.10`, role names) with your own.

## How a query is built

Every query is a chain of steps joined by `|`, read top to bottom:

| Command | What it does | Example |
|---------|--------------|---------|
| `fields` | Choose the columns to show | `fields @timestamp, eventName` |
| `filter` | Keep only matching rows | `filter eventName = "StopLogging"` |
| `sort` | Order the rows | `sort @timestamp desc` (newest first) |
| `limit` | Show only the first N rows | `limit 20` |
| `stats` | Count or group rows | `stats count(*) by eventName` |
| `parse` | Pull a piece out of a text field | `parse userIdentity.arn "assumed-role/*/*" as role, session` |

Useful CloudTrail fields:

| Field | Meaning |
|-------|---------|
| `eventName` | The API call, such as `StopLogging` or `DescribeInstances` |
| `eventSource` | The service, such as `ec2.amazonaws.com` |
| `userIdentity.arn` | Who made the call (user or role and session) |
| `userIdentity.type` | `AssumedRole`, `IAMUser`, `Root` or `AWSService` |
| `sourceIPAddress` | Where the call came from (an IP address or an AWS service name) |
| `errorCode` | Empty if the call worked, such as `AccessDenied` if it failed |
| `requestParameters.*` | What the caller asked for (the details of the call) |
| `awsRegion` | Region the call was made in |

Things to remember:

- Matching is **case-sensitive**: `"stoplogging"` won't find `StopLogging`.
- `=` matches exactly; `like /text/` matches part of a value (a regex, or
  "regular expression").
- **Blind spot:** this lab's trail is single-Region (us-east-2). IAM, STS
  global-endpoint and console sign-in events are recorded in us-east-1 and
  won't show up unless the trail is multi-Region.
- You pay per gigabyte scanned. Short time ranges keep it at fractions of a cent.

---

## Basic

### B1. What happened most recently?
The first look in any investigation.
```
fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, errorCode
| sort @timestamp desc
| limit 20
```

### B2. Find one specific action
Swap in any event name: `DeleteTrail`, `CreateKeyPair`, `DisableKey`.
```
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventName = "StopLogging"
| sort @timestamp desc
```

### B3. Find several actions at once
```
fields @timestamp, eventName, userIdentity.arn
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail", "DeleteLogGroup"]
| sort @timestamp desc
```

### B4. Every failed call
Failures are where recon shows up.
```
fields @timestamp, eventName, errorCode, userIdentity.arn, sourceIPAddress
| filter ispresent(errorCode)
| sort @timestamp desc
```

### B5. Everything one identity did
Use part of the role or user name.
```
fields @timestamp, eventName, eventSource, errorCode, sourceIPAddress
| filter userIdentity.arn like /cdl-d05-recon-test/
| sort @timestamp asc
```
`asc` puts it in time order, which reads like a story.

### B6. Everything from one IP address
```
fields @timestamp, eventName, userIdentity.arn, errorCode
| filter sourceIPAddress = "203.0.113.10"
| sort @timestamp asc
```

### B7. Changes only (hide reads)
Most events are lookups; changes are what matter.
```
fields @timestamp, eventName, eventSource, userIdentity.arn
| filter eventName not like /^(Get|List|Describe|Lookup|Head)/
| sort @timestamp desc
| limit 50
```

### B8. Humans only (hide AWS services)
Removes the background noise of AWS services calling each other.
```
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter userIdentity.type != "AWSService"
| sort @timestamp desc
| limit 50
```

### B9. Anything done by the root user
The root user should almost never be used. Any row here is worth a look.
```
fields @timestamp, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| sort @timestamp desc
```

---

## Intermediate

### I1. Which API calls are most common?
A baseline of "normal", so the unusual stands out.
```
stats count(*) as calls by eventSource, eventName
| sort calls desc
| limit 25
```

### I2. Activity over time
Spikes in 5-minute buckets. Click **Visualization** to see it as a chart.
```
stats count(*) as events by bin(5m)
| sort events desc
```

### I3. Denied-call bursts (what D05 alarms on)
Who got denied at least 5 times in any 5-minute window. `filter` after
`stats` keeps only the groups that pass.
```
filter errorCode like /AccessDenied|UnauthorizedOperation/
| stats count(*) as denied by userIdentity.arn, bin(5m) as window
| filter denied >= 5
| sort denied desc
```

### I4. Error rate per identity
An identity that fails a large share of its calls is often probing.
```
fields ispresent(errorCode) as failed
| stats count(*) as total, sum(failed) as errors by userIdentity.arn
| fields userIdentity.arn, total, errors, errors * 100 / total as error_pct
| sort error_pct desc
```

### I5. How many services did each identity touch?
Recon tends to sweep many services quickly (MITRE ATT&CK T1580).
```
filter userIdentity.type != "AWSService"
| stats count_distinct(eventSource) as services, count(*) as calls by userIdentity.arn
| sort services desc
```

### I6. When was each IP first and last seen?
A new IP address for a known identity can mean stolen credentials.
```
filter userIdentity.type != "AWSService"
| stats earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen, count(*) as calls by userIdentity.arn, sourceIPAddress
| sort first_seen desc
```

### I7. Group by role name, not session
Role sessions have random-looking IDs. `parse` pulls out just the role name.
```
filter userIdentity.type = "AssumedRole"
| parse userIdentity.arn "assumed-role/*/*" as role, session
| stats count(*) as calls, count_distinct(session) as sessions by role
| sort calls desc
```

### I8. Who took on which role?
Role switching is how attackers move around (MITRE ATT&CK T1078.004).
Only calls to STS's regional endpoint appear in a single-Region trail.
```
fields @timestamp, userIdentity.arn, requestParameters.roleArn, requestParameters.roleSessionName, sourceIPAddress
| filter eventName = "AssumeRole"
| sort @timestamp desc
```

### I9. Firewall opened to the whole internet (what D02 alarms on)
Searches the raw event text for `0.0.0.0/0`.
```
fields @timestamp, userIdentity.arn, requestParameters.groupId, sourceIPAddress
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter @message like /0\.0\.0\.0\/0/
| sort @timestamp desc
```

### I10. Rebuild an attack timeline
Every change and failure by one identity, in order. Pair it with B5 or B6
once an alert names a suspect.
```
fields @timestamp, eventName, eventSource, errorCode, sourceIPAddress
| filter userIdentity.arn like /cdl-d05-recon-test/
| filter ispresent(errorCode) or eventName not like /^(Get|List|Describe|Lookup)/
| sort @timestamp asc
```

### I11. Unusual tools (user agents)
Each call records the tool that made it. Something other than the console,
the CLI (command-line interface) or Terraform deserves a look.
```
filter userIdentity.type != "AWSService"
| stats count(*) as calls by userAgent, userIdentity.arn
| sort calls asc
| limit 25
```
`asc` puts the rarest tools first. Rare is what you're hunting for.

---

## A typical hunt, start to finish

1. **An alert fires** (say D05). Run **I3** to see who crossed the line.
2. **Scope the suspect.** Run **B5** with that identity, then **I6** for its IP
   addresses.
3. **Widen out.** Run **B6** with the IP: did anyone else call from there?
4. **Check for damage.** Run **B7** and **I10**: did any changes succeed?
5. **Write it up:** who, what, when, from where, and what you did about it.
