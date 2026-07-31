# Security Queries

This repository contains KQL queries, PowerShell scripts, and Python tooling used for security operations, threat hunting, phishing investigation, identity monitoring, endpoint review, and Microsoft 365 security analysis.

## Categories

- Phishing investigation
- Phishing email triage and IOC extraction (Python)
- Account compromise hunting (Defender Advanced Hunting)
- Identity and sign-in analysis
- Exchange Online forwarding and inbox-rule checks

## Layout

```
KQL/
  Phishing/                       Email/URL/attachment correlation
  AccountCompromise/              Full mailbox-compromise playbook
    PLAYBOOK.md                   Method, connection guide, scenario router, phases
    1-scope.kql                   How far did it go? Who has to be called?
    2-persistence.kql             Is the door still open after a reset?
    3-actor.kql                   Who, from where, separable from the user?
    4-impact.kql                  IT cleanup, or a notification obligation?
    5-program.kql                 Why wasn't it caught?
PowerShell/
  ExchangeOnline/                 Connect, inbox-rule review, forwarding sweeps
Python/
  PhishingTriage/                 saved message or export -> IOCs and a hunt
    triage.py                     Headers, spoofing checks, Safe Links, .msg
    README.md                     Usage, safety constraints, limitations
    samples/                      Synthetic .eml/.msg fixtures and a CSV export
```

`Python/PhishingTriage` sits in front of the KQL. It takes saved messages —
`.eml`, Outlook `.msg`, or Defender's password-protected ZIP — or an Advanced
Hunting CSV export, unwraps Defender Safe Links back to the true destination,
extracts the indicators, and generates the query that finds everyone else who
received the same message — the handoff into `KQL/`.

Three modes: one message, a campaign (several files or a directory), or `--csv`
straight from a hunting export when you never downloaded the message at all.
Campaign mode produces the deduplicated recipient list, the delivery breakdown,
and one query covering the union of every indicator.

`.msg` is read directly, without a library. Outlook keeps the complete original
RFC 822 header block in a single MAPI property, so once the OLE compound file is
parsed the `.eml` path handles the rest unchanged.

Standard library only, so it runs where `pip install` is a ticket. It never
fetches an extracted URL and never uploads an attachment; see its README for why
both are enforced in code rather than by convention.

Start with `KQL/AccountCompromise/PLAYBOOK.md`. It covers:

- The four gotchas that silently invalidate results — UTC `datetime()` literals,
  the 30-day hunting window, unreliable display-name fields, and hunting being
  read-only.
- **Which tool answers which question**, with the retention limit on each. KQL
  tells you what happened; PowerShell tells you what is true right now.
- **Connecting to Exchange Online, Purview, and Graph** before you hunt, and the
  role each task requires.
- **A scenario router** mapping what you are actually holding — a risky sign-in,
  an inbox rule, external forwarding, an OAuth grant — to the phases it needs and
  the step most often skipped.
- The five phases in detail, and six habits that outlast the query syntax.

## Disclaimer

All queries and scripts are sanitized and use placeholder values. No sensitive, internal, or production data is included.
