# Phishing Email Triage

Reads saved `.eml` files or an Advanced Hunting export, reports what is
observable in them, and generates a Defender Advanced Hunting query built from
the indicators it found.

```bash
python3 triage.py suspicious.eml                    # one message
python3 triage.py ./incident-4471/                  # a campaign
python3 triage.py --csv EmailEvents-export.csv      # straight from hunting
```

Standard library only — no `pip install`, which matters on a managed workstation
where installing a package is a ticket. Python 3.7+.

It reports observations. It does not return a verdict. Nothing in the output
distinguishes a phish from a badly configured newsletter on its own, and a tool
that guesses at a verdict trains you to stop reading the evidence.

## What it replaces

The manual version of this is: open the headers, compare From against Reply-To,
find the SPF/DKIM/DMARC line in the wall of text, copy the links out, decode any
Safe Links wrapper by hand, hash the attachments, then retype all of it into a
KQL query to find who else got it. Ten to fifteen minutes, every time, and the
step people skip when busy is the last one — which is the only step that finds
the other forty recipients.

## Three modes

**One message.** A single `.eml` gives the full per-message report: every
header, the Received chain, findings with reasoning, and a query scoped to that
sender.

**A campaign.** Several `.eml` files, or a directory of them, switch to campaign
mode — one combined report and one query covering the whole set, instead of N
reports to merge by hand.

**An Advanced Hunting export.** `--csv` reads the CSV you get from exporting an
`EmailEvents` query, optionally joined with `EmailUrlInfo` or
`EmailAttachmentInfo`. No `.eml` needed at all, which matters when you are
working an incident from inside Defender and never downloaded the message.

Campaign mode answers what per-message triage cannot:

- **The recipient list**, deduplicated across every message. This is the
  notification list. Reconcile it against whatever the notification team is
  working from — if yours is longer, go back to them today.
- **The delivery breakdown** — how many copies were blocked, how many landed in
  Junk, how many are sitting in an inbox right now.
- **Findings collapsed across messages**, so you see the shape of the campaign
  rather than the same paragraph forty times.
- **The union of indicators** in a single query, so one hunt covers all of it.

`EmailEvents` emits one row per recipient, so CSV rows are grouped by
`NetworkMessageId` before anything is counted. Skip that and a message sent to
forty people counts as forty messages and every total in the report is wrong.

A CSV has no headers, no body, and no attachment bytes. The checks that read
those are skipped rather than reported as clean — no display name, no anchor
text, no Received chain, no attachment filenames. What survives is the part that
matters most at campaign scale: sender alignment (`SenderMailFromAddress` is the
same envelope identity the Return-Path carries), the authentication verdicts out
of `AuthenticationDetails`, delivery outcome, the recipient list, and the URLs —
still Safe Links-unwrapped if the export carried them.

That last point is worth seeing. Export three copies of one phish and you get
three different Safe Links wrappers, because the `data=` parameter is
per-recipient. Unwrapped, they collapse to the one destination you actually
need to block.

## Getting a `.eml` in the first place

A `.eml` is the raw message as it travelled over the wire, saved as text:
headers, a blank line, then the body, with attachments base64-encoded further
down. Open one in a text editor and it is all readable. That is the point —
Outlook renders a display name and a clean-looking link, and the `.eml` holds
the sender address, the authentication results, the routing chain, and the URL
the link actually points at.

**`.msg` is not `.eml`.** Classic Outlook for Windows saves `.msg` by default —
dragging a message to the desktop, or File > Save As, both produce it. That is a
binary OLE compound file, not text. This tool refuses it with a message saying
so rather than producing garbage from it.

Paths that give you an actual `.eml`:

| Source | How |
|--------|-----|
| **Defender XDR** (preferred) | Threat Explorer or the Email entity page > **Download email**. Requires the Preview role, which is separate from read-only hunting — check you have it before you need it mid-incident. |
| **Outlook on the web** | Open the message > `...` > **Download**. |
| **Outlook for Mac** | Drag to Finder, or File > Save As. |
| **User-reported via Report Message** | Pull the original from Defender > Actions & submissions > Submissions. |

Defender is the right default. You are already in it when you are investigating,
the user does not have to do anything, and you get the message as Microsoft
received it rather than a copy that has been through a mail client.

Menu wording moves between Outlook builds. Whatever the version, you are looking
for Download or a Save As that offers `.eml`.

Check you got a good one:

```bash
head -20 reported-phish.eml
```

Readable `Received:` and `From:` lines mean you are fine. Binary noise means you
have a `.msg`.

**If the user forwarded the phish as an attachment**, the file you have is their
forwarding wrapper — their headers, their authentication results, all clean by
definition, and none of them the sender's. Triaging that tells you nothing about
the phish. This tool detects the attached `message/rfc822` and triages the
original instead, and says so in the output. `--no-unwrap-forwarded` if you want
the wrapper.

The downloaded `.eml` still contains the attachments. It is inert as long as
nothing extracts and runs them — this tool only hashes the bytes in memory, and
never writes them out. Do not double-click the file to "check it," and do not
unpack attachments from it on your workstation.

## What it checks

**Headers.** From, Reply-To, Return-Path, Message-ID, the full Received chain,
and Authentication-Results (SPF, DKIM, DMARC, compauth). Also
`X-Forefront-Antispam-Report`, which is what Exchange Online Protection
concluded at delivery — SCL, the CAT category, and SFV.

`SFV:SKN` or `SCL:-1` on a message you have decided is malicious is its own
finding: filtering was *bypassed*, not passed. An allow-list entry, a mail-flow
rule, or a connector told EOP not to filter. Find that rule before you close the
ticket, because it will pass the next one too.

**Sender mismatches**, by string comparison — no lookups, no network:

- From domain against Return-Path (envelope sender) domain. SPF authenticates
  the Return-Path, not the From the user sees, so a pass proves the envelope
  domain authorised the sending IP and proves nothing about the From address.
- From domain against Reply-To domain. The mechanism of most BEC: the message
  looks like a known party and the reply goes somewhere else.
- Display name containing an email address that is not the sender's. Clients
  show the display name and hide the address, especially on mobile, so the
  recipient sees the address they expect and never sees the one that gets the
  reply.
- Punycode (`xn--`) and non-ASCII in the sender identity.

Return-Path and Reply-To splits are also completely normal for bulk mail. The
severity is softened when the domains share a registrable suffix, and the
question is always whether the other domain is one you can account for — not
whether the fields differ.

**Link text against link destination.** An anchor reading `portal.contoso.com`
whose `href` goes to `portal-contoso.example.net`. The recipient reads the text;
the client follows the href. When the message has been Safe Links-rewritten,
hovering shows the wrapper rather than either one, so the user has no way to see
this at all.

**Attachments.** SHA256 and MD5, size, content type, and a note on extensions
worth reading out loud — HTML, disk images, script types, macro-enabled Office,
OneNote. Double extensions (`Remittance.pdf.html`) are flagged separately: only
the final extension decides what opens it, and the first one is there to be read
by a person. Archives are listed but never unpacked; that belongs in a sandbox.

## Safe Links unwrapping

Defender rewrites inbound URLs at delivery:

```
https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal-contoso
.example.net%2Fmfa%2Freset%3Fid%3D9f2a1c&data=05%7C02%7Cavery.nakamura%40contoso
.com%7C4d1f8c2b6a7e4f0c9d3a08dc&sdata=...&reserved=0
```

The wrapper is what sits in the mailbox. The destination is what you block,
search for, and look up. Getting this wrong is not a small error — pasting a
Safe Link into VirusTotal returns a clean verdict on `outlook.com`, which reads
exactly like a clean verdict on the phish.

This unwraps recursively, handles the double-encoding you get when the original
URL was already percent-encoded before Microsoft touched it, and covers the
regional (`nam01`, `eur04`, ...) and GCC (`.office365.us`) hosts. Proofpoint URL
Defense v2 and v3 are handled as well, since mail often crosses more than one
gateway. Both the original and the destination are kept in the output.

**Safe Links wrappers are deliberately left out of the generated KQL.** The
wrapper carries per-recipient `data=` and `sdata=` parameters, so matching on it
finds only the copy you already have. `EmailUrlInfo` and `UrlClickEvents` record
the true destination, and that is what goes in the query.

## The KQL handoff

The generated query drops straight into Defender XDR > Hunting > Advanced
hunting, with the indicators already filled in. Sections are numbered as
emitted; run them one at a time.

1. **Every message from this sender** — `EmailEvents` filtered on the extracted
   sender addresses and domains. Who else got it, and where it landed.
2. **URL-first sweep** — `EmailUrlInfo` joined back to `EmailEvents`. Run this
   even when section 1 looked contained. Campaigns rotate the sending domain and
   keep the landing page, so a sender-scoped search reports a campaign as one
   message.
3. **Clicks** — `UrlClickEvents`. `IsClickedThrough` non-zero means the user
   overrode the block page. Those users are the containment list; treat them as
   credential-entered until shown otherwise and go to
   [`KQL/AccountCompromise/PLAYBOOK.md`](../../KQL/AccountCompromise/PLAYBOOK.md).
4. **Attachment hashes** — `EmailAttachmentInfo`, then `DeviceFileEvents`. A hit
   in the second means it left the mailbox and reached an endpoint, which makes
   this endpoint work rather than email triage.
5. **The sending IP** — baseline it over 30 days before calling it hostile. An
   IP that appears across weeks is shared sending infrastructure.
6. **Same subject, different sender** — noisy by design. Read the sender list,
   not the row count.

The query uses `ago()` throughout rather than `datetime()` literals, which are
always UTC no matter what the portal displays — the first of the four gotchas in
the account-compromise playbook. Advanced hunting retains 30 days; beyond that,
absence in Defender means nothing at all and you need Purview.

## Enrichment

Off unless you ask for it:

```bash
export VT_API_KEY=...
export URLSCAN_API_KEY=...
python3 triage.py suspicious.eml --enrich
```

VirusTotal by URL, domain, sending IP, and attachment SHA256; urlscan.io by
domain. Free-tier VirusTotal is 4 requests/minute and 500/day, so requests are
paced 15 seconds apart and capped at 8 per run (`--vt-rate`, `--max-lookups`).
Blowing the daily quota mid-incident is worse than waiting.

### Safety constraints

These are enforced in code, not just documented.

**Look up, never submit.** VirusTotal is queried by URL and by file hash. A
lookup of a SHA256 answers "has anyone seen this file" without the file going
anywhere. Any actual submission sits behind `--submit`, which is off by default
and does nothing without `--enrich`.

**Attachments are never uploaded, with or without `--submit`.** There is no
file-upload code path in this tool at all. Uploading an attachment pulled from a
user's mailbox ships whatever that mailbox contained to a third party, where on
the free tier other customers can download it. The hash answers the same
question. If a sample genuinely has to be detonated, that is a deliberate
decision made with a sandbox, not a side effect of running a triage script.

**Extracted URLs are never fetched from the workstation.** No `urlopen` on a
suspicious link, ever. The single outbound HTTP function checks the hostname
against an allowlist of the reputation APIs and raises otherwise, so a future
change that tried to request an extracted URL fails loudly instead of quietly
detonating a payload on a SOC analyst's machine. Reputation lookups only;
detonation belongs in a sandbox.

**URLs that embed a recipient address are never submitted, and are looked up by
domain instead.** Credential-harvest links routinely pre-fill the victim's
address in the query string or a base64 fragment. A public scan of one
republishes who was targeted. Submissions that do happen are forced to
`visibility: unlisted`.

## Getting a CSV out of Advanced Hunting

Run a query in Defender XDR > Hunting > Advanced hunting, then **Export** the
results. Keep the sender columns — the tool needs at least one of
`SenderFromAddress` or `SenderMailFromAddress` and will tell you if they are
missing. Everything else is optional and adds detail when present.

A starting query, given a sender or a URL you already have:

```kql
let lookback = 14d;
EmailEvents
| where Timestamp > ago(lookback)
| where SenderFromDomain =~ "contoso-it.example.org"
| join kind=leftouter (EmailUrlInfo | project NetworkMessageId, Url, UrlDomain)
    on NetworkMessageId
| project Timestamp, NetworkMessageId, InternetMessageId, Subject,
          SenderFromAddress, SenderMailFromAddress, SenderFromDomain,
          SenderMailFromDomain, SenderIPv4, RecipientEmailAddress,
          DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods,
          AuthenticationDetails, Url, UrlDomain
```

Export that, feed it in, and the tool gives you the campaign shape, the
recipient list, and a *refined* query built from everything it found — including
sender domains and URL destinations that were not in your original filter.

Column names are resolved through a list of aliases, so an export that renamed
`SenderFromAddress` to `SenderAddress` still works.

## Output

Markdown to stdout by default. `--format json` or `--format kql` to pick a
different one, or write all three at once:

```bash
python3 triage.py suspicious.eml --outdir ./out
```

Giving `out/suspicious-triage.md` for the ticket, `out/suspicious-iocs.json` for
anything downstream, and `out/suspicious-hunt.kql` for Defender. In campaign
mode the files are named `campaign-*`, or after the CSV.

In campaign mode, enrichment runs once across the union of indicators rather
than once per message — otherwise a forty-message campaign spends its entire
VirusTotal quota looking up the same URL forty times.

URLs, domains and IPs are defanged in the Markdown so a ticketing system does
not linkify them — tickets get read by people who click. The JSON and the KQL
carry real values, because those feed machines. `--no-defang` to turn it off.

## What it does not do

Worth knowing before you trust a clean result:

- **HTML is read with regex, not a parser.** Obfuscation a browser would resolve
  — entity-encoded hrefs, links built by script, attributes split across tags —
  is missed. Anything that matters gets confirmed against `EmailUrlInfo`, which
  saw what Defender saw.
- **No DNS, WHOIS, or domain-age lookups.** Nothing resolves a hostname.
- **No lookalike-domain detection beyond flagging punycode.** It will not tell
  you `rnicrosoft.com` resembles anything. Comparing codepoints is a human step.
- **Received headers below your own boundary are attacker-supplied text** and
  can be fabricated wholesale. The earliest public hop is reported as a lead;
  confirm it against `EmailEvents.SenderIPv4` before it goes in a report.
- **`.msg` is not supported.** See above.
- **A clean run is not a clean bill of health.** It means these specific checks
  found nothing.

## Samples

`samples/` holds five synthetic fixtures — no real email content:

| File | What it exercises |
|------|-------------------|
| `01-safelinks-credential-phish.eml` | Safe Links unwrapping, link-text mismatch, SPF/DMARC/compauth fail |
| `02-bec-display-name-spoof.eml` | Display name carrying a different address, Reply-To swap, **all authentication passing** |
| `03-html-attachment-lure.eml` | HTML attachment, double extension, bare-IP URL, `CAT:HPHSH` |
| `04-benign-bulk-newsletter.eml` | Legitimate mail that trips the Return-Path check and nothing else |
| `05-lookalike-domain-user-reported.eml` | User-reported wrapper around the real phish, punycode domain, userinfo-before-host URL |

Plus `hunting-export-EmailEvents.csv` — a five-row Advanced Hunting export
covering three messages across two senders, with per-recipient Safe Links
wrappers that collapse to one destination, and a mixed delivery outcome
(inbox / junk / quarantine).

```bash
python3 triage.py samples/01-safelinks-credential-phish.eml   # one message
python3 triage.py samples/                                    # campaign mode
python3 triage.py --csv samples/hunting-export-EmailEvents.csv
```

Fixture 2 is the one worth reading carefully. SPF, DKIM, DMARC and compauth all
pass, because the attacker's own domain is properly configured — authentication
proves the message came from the domain in the From header and proves nothing
about whether that domain should be trusted. Fixture 4 is the other direction: a
real newsletter that trips a check, so the output shows what a false positive
looks like next to a true one.

The victim organisation is `contoso.com`, the repo-wide placeholder. Everything
attacker-side uses RFC 2606 reserved domains (`example.com`, `example.net`,
`example.org`) and RFC 5737 documentation IP ranges, so nothing in the fixtures
can resolve or be registered. The HTML attachment in fixture 3 is an inert stub
with no script, no form, and no redirect.
