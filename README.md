# Security Queries

This repository contains KQL queries and PowerShell scripts used for security operations, threat hunting, phishing investigation, identity monitoring, endpoint review, and Microsoft 365 security analysis.

## Categories

- Phishing investigation
- Account compromise hunting (Defender Advanced Hunting)
- Identity and sign-in analysis
- Exchange Online forwarding and inbox-rule checks

## Layout

```
KQL/
  Phishing/                       Email/URL/attachment correlation
  AccountCompromise/              Full mailbox-compromise playbook
    PLAYBOOK.md                   Method, phase guide, and the ground rules
    1-scope.kql                   How far did it go? Who has to be called?
    2-persistence.kql             Is the door still open after a reset?
    3-actor.kql                   Who, from where, separable from the user?
    4-impact.kql                  IT cleanup, or a notification obligation?
    5-program.kql                 Why wasn't it caught?
PowerShell/
  ExchangeOnline/                 Connect, inbox-rule review, forwarding sweeps
```

Start with `KQL/AccountCompromise/PLAYBOOK.md` — it covers the four
result-invalidating gotchas (UTC literals, 30-day retention, unreliable
display-name fields, read-only hunting) and the method behind the queries.

## Disclaimer

All queries and scripts are sanitized and use placeholder values. No sensitive, internal, or production data is included.
