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

## The five phases

| File | Phase | The question |
|------|-------|--------------|
| `1-scope.kql`       | Scope       | How far did it go? Who has to be called? |
| `2-persistence.kql` | Persistence | Is the door still open after a reset? |
| `3-actor.kql`       | Actor       | Who, from where, and is it separable from the user? |
| `4-impact.kql`      | Impact      | IT cleanup, or a notification obligation? |
| `5-program.kql`     | Program     | Why wasn't it caught? |

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
