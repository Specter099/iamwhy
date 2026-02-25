# iamwhy

Explains AWS IAM access denials from the command line. Given an IAM principal and an action that's being denied, `iamwhy` traces exactly why: which policy, which statement, which condition is blocking it.

## Quick start

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

iamwhy alice s3:GetObject
iamwhy arn:aws:iam::123456789012:role/MyRole ec2:TerminateInstances \
    --resource "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"
```

## Usage

```
iamwhy PRINCIPAL ACTION [OPTIONS]

Arguments:
  PRINCIPAL   IAM user ARN, role ARN, STS assumed-role session ARN,
              bare username, or bare role name
  ACTION      AWS action string, e.g. s3:GetObject

Options:
  --resource TEXT       Resource ARN (default: *)
  --context KEY=VALUE   Context entry (repeatable)
  --output [text|json]  Output format (default: text)
  --profile TEXT        AWS credentials profile ($AWS_PROFILE)
  --region TEXT         AWS region ($AWS_DEFAULT_REGION)
```

## Example output

```
Principal: arn:aws:iam::123456789012:user/alice
Action:    s3:GetObject
Resource:  arn:aws:s3:::my-bucket/data.csv

Verdict: DENIED (explicit deny)

Reason: An explicit Deny statement in "DenyPublicS3" overrides any Allow.

╭─ arn:aws:iam::123456789012:policy/DenyPublicS3 (IAMPolicy) ─╮
│ Statement: Sid=DenyS3Public                                  │
│   Effect:  Deny                                              │
│   Action:  s3:*                                              │
│   Resource: *                                                │
╰──────────────────────────────────────────────────────────────╯

Decision breakdown:
  DenyPublicS3         explicitDeny
  AmazonS3FullAccess   allowed

Missing context: (none)
```

## JSON output

```bash
iamwhy alice s3:GetObject --output json | jq .cause
# "explicit_deny"
```

The JSON schema:
```json
{
  "principal": "arn:...",
  "principal_type": "user",
  "action": "s3:GetObject",
  "resource": "*",
  "decision": "explicitDeny",
  "cause": "explicit_deny",
  "summary": "...",
  "orgs_blocked": false,
  "boundary_blocked": false,
  "missing_context": [],
  "blocking_policies": [{"policy_id": "...", "decision": "...", "statement": {...}}],
  "all_breakdown": [{"policy_id": "...", "decision": "..."}]
}
```

## Cause values

| Cause | Description |
|---|---|
| `explicit_deny` | A Deny statement in a policy explicitly blocks the action |
| `implicit_deny` | No Allow was found; the default deny applies |
| `scp_block` | An AWS Organizations SCP denies the action |
| `permissions_boundary` | The principal's permissions boundary does not allow the action |
| `missing_context` | A condition could not be evaluated due to absent context keys |
| `combined` | Multiple of the above apply simultaneously |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Access allowed |
| `1` | Access denied |
| `2` | Usage error or AWS API error |

## Required permissions

`iamwhy` needs the following IAM permissions for the credentials you run it with:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:SimulatePrincipalPolicy",
    "iam:GetUser",
    "iam:GetRole",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetUserPolicy",
    "iam:GetRolePolicy",
    "iam:ListAttachedUserPolicies",
    "iam:ListUserPolicies",
    "iam:ListGroupsForUser",
    "iam:ListAttachedGroupPolicies",
    "iam:ListGroupPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies"
  ],
  "Resource": "*"
}
```

`iam:GetPolicy*` and `iam:List*` are optional — `iamwhy` degrades gracefully if they are absent, showing the policy ID without the statement text.

## Development

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
coverage run -m pytest && coverage report
```
