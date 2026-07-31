# Email Account Compromise — Hunting Playbook

A reusable playbook for investigating a compromised Microsoft 365 mailbox in
Defender Advanced Hunting. Queries are grouped by the **question they answer**,
not by table. Each `.kql` file in this folder is one phase; run sections
individually and replace the `let` placeholders at the top of each.

## Before you start — four things that silently invalidate results

1. **KQL `datetime()` literals are always UTC**, no matter what the portal
   displays. Convert your window before you build it. A query that returns
   nothing because the window was wrong looks identical to one that returns
   nothing because nothing happened.
2. **Advanced hunting retains 30 days.** Older events need Purview Audit or
   `Search-UnifiedAuditLog`. Export anything you need to keep.
3. **Display-name fields are unreliable.** `AccountDisplayName` sometimes holds
   the user, sometimes an application, sometimes nothing. Resolve to
   `AccountObjectId` before committing a conclusion to a report.
4. **Advanced hunting is read-only.** It will not show a mailbox rule's current
   state or remediate anything — that is Exchange Online PowerShell. Expect to
   need both.

## Which tool answers which question

KQL tells you what happened. PowerShell tells you what is true right now. You
need both, and neither is complete alone. A rule can be created and deleted
inside the log window, leaving nothing in the mailbox. A rule can also sit in a
mailbox with no surviving log entry because it predates retention. Reaching for
one tool and stopping is how an investigation closes over a live persistence
mechanism.

| The question | Tool | Retention |
|--------------|------|-----------|
| What happened in the last 30 days | Defender XDR · Advanced hunting | 30 days |
| What happened 30–180 days ago | `Search-UnifiedAuditLog` (Purview) | 90 days, 1 year on E5 |
| What rules or forwarding exist right now | Exchange Online PowerShell | Live state |
| Who signed in, from where, did CA apply | Entra ID · Sign-in logs | 30 days |
| Who received and who clicked | Defender · Threat Explorer | 30 days |
| Which mailboxes still hold the message | Threat Explorer · purge | Live state |
| What the actor did after access | `CloudAppEvents` (KQL) | 30 days |

Start in Defender to build the timeline, confirm in PowerShell for current
state, and fall back to `Search-UnifiedAuditLog` the moment the incident
predates the hunting window. **Outside 30 days, absence in Defender means
nothing at all.**

## Connect before you hunt

Advanced hunting cannot show a rule's current state and cannot remove one. Every
Phase 2 finding eventually lands in PowerShell. Connect before you start
hunting, not after you find something — the module install and the MFA prompt
are not what you want between discovering a forwarding rule and removing it.

```powershell
# One-time, on a new machine
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# Every session, before any Phase 2 query
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName you@contoso.com
Get-OrganizationConfig | Select-Object Name, DisplayName
```

Confirm the tenant before running anything that changes state. Connecting to the
wrong tenant and removing the wrong rule is recoverable only if you notice.

```powershell
# Events older than 30 days, or identity containment
Connect-IPPSSession -UserPrincipalName you@contoso.com
Connect-MgGraph -Scopes "User.ReadWrite.All","AuditLog.Read.All",
                        "Directory.Read.All","UserAuthenticationMethod.ReadWrite.All"
```

When a Phase 2 query returns a hit, read live state before changing anything —
`Description` states the rule's full logic in plain English, and that is your
evidence once the rule is gone:

```powershell
Get-InboxRule -Mailbox <mailbox> | Format-List Name,Enabled,Description,
    MoveToFolder,ForwardTo,RedirectTo,DeleteMessage,MarkAsRead,StopProcessingRules
Get-Mailbox <mailbox> | Format-List ForwardingSmtpAddress,ForwardingAddress,
    DeliverToMailboxAndForward
```

**Mailbox-level forwarding and inbox rules are configured separately.**
`Get-InboxRule` will never show `ForwardingSmtpAddress`. Removing one and
missing the other leaves the incident open while reading as closed.

Disconnect when done (`Disconnect-ExchangeOnline -Confirm:$false`,
`Disconnect-MgGraph`) — sessions persist and count against a connection limit.

| Task | Role |
|------|------|
| Read inbox rules, mailbox configuration | View-Only Recipients (Exchange Online) |
| `Search-UnifiedAuditLog` | View-Only Audit Logs, or Audit Logs |
| Remove rules, clear forwarding, block sign-in | Mail Recipients / Organization Management |
| Revoke sessions, reset MFA methods | Authentication Administrator (Entra ID) |

A cmdlet that returns "not recognized" after a successful connect is almost
always a missing role, not a typo. Check the role assignment before debugging
the syntax.

## The five phases

| File | Phase | The question |
|------|-------|--------------|
| `1-scope.kql`       | Scope       | How far did it go? Who has to be called? |
| `2-persistence.kql` | Persistence | Is the door still open after a reset? |
| `3-actor.kql`       | Actor       | Who, from where, and is it separable from the user? |
| `4-impact.kql`      | Impact      | IT cleanup, or a notification obligation? |
| `5-program.kql`     | Program     | Why wasn't it caught? |

### Scenario router — where to start

The phases are ordered for a full investigation. A live alert rarely needs all
five in sequence. Find what you are actually holding, and run those phases in
that order.

| What you are holding | Phases | The step most often skipped |
|----------------------|--------|-----------------------------|
| Risky sign-in after a phishing URL click; known AiTM infrastructure | 3 → 2 → 1 → 4 | Phase 2. Revoking the session evicts the attacker; it does not remove what they configured. |
| Inbox rule created or modified, no other signal | 3 → 2 | Baseline the address before calling it hostile. Most of these are a user filing mail. |
| Impossible travel, atypical sign-in properties | 3 → 1 | Confirm the sign-in succeeded. Failed attempts are noise, and a success with no subsequent activity usually is too. |
| Outbound spam, or a user reports mail they did not send | 1 → 2 → 4 | The external recipient list in Phase 1. That is a disclosure duty, not an internal cleanup. |
| External forwarding found on a mailbox | 2 → 4 → 1 | `Set-Mailbox` forwarding is separate from inbox rules. Check both or you have removed half of it. |
| Suspicious OAuth consent or app grant | 2 → 3 → 4 | Consented applications survive both a password reset and session revocation. |
| Any activity on a shared or service mailbox | 3 → 2 → 1 | Establish delegated access versus direct sign-in before attributing the action to anyone. |
| Quarantine release under review, or a user-reported phish | 1 → 5 | Detonate the URL before releasing. Sender legitimacy is precisely what vendor compromise defeats. |

**Phase 3 comes first on any single-user alert.** Until the actor is separated
from the user, every list built in Phase 1 is contaminated with the user's own
behaviour, and the notification list you hand over is wrong in both directions.

**No path skips Phase 2.** A rule, a forward, a consent grant, or a registered
MFA method survives every credential action you take. An incident closed without
Phase 2 is not closed.

### Phase 1 — Scope
Answer before containment feels finished. Group outbound by subject; a campaign
is one subject with a huge count. **Reconcile your recipient count against the
notification team's list** — if yours is bigger, go back to them today. The
first-appearance-of-a-URL query tells you whether the lure arrived by email at
all: if the earliest hit is the user's own outbound message, corporate email is
eliminated as the vector.

### Phase 2 — Persistence
Everything here survives a password reset and session revocation. **`Get-InboxRule`
shows only what exists now** — a rule created and later deleted leaves nothing in
the mailbox but is permanent in `CloudAppEvents`. Absence today is not evidence
none existed yesterday. Check forwarding, delegation, and consented apps too;
consent grants need no password.

### Phase 3 — Actor
Baseline first. An IP spanning weeks is home or office; one that appears cold and
burns out in two days is infrastructure. Residential ISPs are not automatically
benign. For IPv6, **match the /64 prefix, not the full address**. When you have a
confirmed hostile event, pivot on its session ID — one session covering the
reads, the rule, and the send is the strongest evidence the tooling produces.

### Phase 4 — Impact
`MailItemsAccessed`, `Send`, and `SoftDelete` are ordinary user activity. They
describe an attacker only once you have **independently** established the actor
was one — so anchor these queries to confirmed hostile infrastructure, never to
the account alone. If a delete-rule was in play, recover the destroyed replies
from mail-flow telemetry, which the rule could not touch.

### Phase 5 — Program
"No alert fired" is three findings with three fixes: the detection didn't exist
(build it), it existed but didn't match (tune it), or it fired and nobody
triaged it (fix routing and staffing). The size of the untriaged high-severity
queue is often the real finding — adding detections to a queue nobody reads
makes the program worse.

## Method — six habits that outlast the queries

The syntax dates; these do not.

- **Ask what a clean result would fail to see.** The findings that matter often
  arrive by refusing a negative — the rules check says clean, the audit log says
  a rule was created and deleted.
- **Validate a null against a known positive.** Before trusting "no results,"
  confirm the same query finds something you know exists. Otherwise "nothing
  happened" and "I asked wrong" are indistinguishable.
- **Baseline before you call anything rare.** Rarity is usually an artifact of
  your filter. Run the identifier unfiltered across the tenant before escalating.
- **Separate observation from conclusion, in different sentences.** "The prefix
  appears on only two days" is observation. "This is attacker infrastructure" is
  conclusion. A reader must be able to reject the second while trusting the first.
- **Check whether an artifact is upstream or downstream of T0.** Nothing after
  the intrusion can explain how it began. Bounces, alerts, and tickets are
  consequences.
- **Re-run scope after every new finding.** The window moves earlier each time
  you look. Trusting the first timeline is how the notification list ends short.
