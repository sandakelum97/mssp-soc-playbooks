# Changelog

All notable changes to this repository. Dates are UTC.

## 2026-10-31 — Codex review follow-up (PR #1)

- `PB-01`, `PB-04` — forwarding removal now clears **both** `ForwardingAddress` (internal) and `ForwardingSmtpAddress`, with a `Get-Mailbox` verification step. Clearing only the SMTP property could leave internal forwarding active.
- `email/05` — includes `Junked` copies (they remain in the Junk Email folder and may still need removal).

## 2026-10-31 — Microsoft Learn alignment update

Every change below was checked against the current Microsoft Learn schema references and incident response guidance (links are in each file's `Ref` line and in the playbooks).

### Added — playbooks (`docs/playbooks/`)
- `PB-00` playbook template (includes a ticket note template)
- `PB-01` Phishing email & credential compromise
- `PB-02` Password spray
- `PB-03` Illicit consent grant & compromised / malicious applications
- `PB-04` AiTM / token theft & BEC
- `PB-05` Human-operated ransomware — pre-encryption response
- `docs/platform-changes.md` — Sentinel → Defender portal (after 31 Mar 2027), `EntraIdSignInEvents`, `Get-MessageTraceV2`, `Search-Mailbox` retirement, audit retention, schema gotchas

### Added — queries
- `identity/07` password spray source IPs (+ accounts with a valid password)
- `identity/08` legacy authentication sign-ins
- `identity/09` device code flow sign-ins
- `identity/10` MFA / security info registered after a risk detection
- `email/05` ZAP and manual remediation status
- `cloud-apps/03` tenant-wide mailbox forwarding and suspicious rule parameters
- `endpoint/11` ransomware pre-encryption indicators
- `entra-apps/01` OAuth consent grant review
- `entra-apps/02` credentials added to apps / service principals
- `entra-apps/03` app role assignments and delegated permission grants

### Fixed — existing queries
- `identity/01` — `take_any(*) by` was missing the `summarize` operator (query would not run).
- `identity/02`, `identity/03` — `RiskEventTypes_V2` is a string column whose empty value is `"[]"`, so `isnotempty()` matched every row; now `!in ("", "[]")`.
- `identity/03`, `identity/04` — `ResultType` is a string in sign-in logs; compare with `"0"`.
- `identity/06` — projected the join's renamed columns explicitly (sign-in IP vs Graph call IP) and documented first-party app-only tokens.
- `email/03` — added a time bound to both sides of the join.
- `email/04` — `DeliveredAsSpam` is not a valid `DeliveryAction` value (`Delivered`, `Junked`, `Blocked`, `Replaced`); added latest delivery columns.
- `endpoint/04` — path check switched to `startswith`.
- `endpoint/06` — `DeviceNetworkEvents` has no `AccountName` column; now `InitiatingProcessAccountName`; public-IP filter tightened.
- `endpoint/07` — `FolderPath !has C:\Windows` excluded rundll32 itself (which lives in System32), so the query missed the attack; now extracts the payload path from the command line and excludes only payloads under `C:\Windows`; extension regex also matches space / end of line.
- `endpoint/02` — only successful logons (`ActionType == "LogonSuccess"`) count as "last logon".
- `email/03` — explicit `kind=inner` join (default `innerunique` kept one random email per account), phish as well as malware, case-insensitive account match.
- `email/04` — case-insensitive recipient match (`in~`).
- `endpoint/10` — `RemoteUrl` normally holds only the host for HTTPS, so the path match never hit; now covers `login.microsoftonline.com` and `login.live.com`; Chromium Edge is `msedge.exe`; header corrected (connections, not POSTs).

### Review pass (independent check of all queries)
- `identity/09` — `OriginalTransferMethod` value is `deviceCodeFlow`; whole-term `has "deviceCode"` never matched.
- `cloud-apps/03` — dynamic values cast with `tostring()` before comparison; `PermanentDelete` / `SoftDeleteMessage` now counted as hiding actions.
- `email/05` — only delivered copies, latest post-delivery action per copy, and copies already in Quarantine / Deleted items / Dropped treated as removed.
- `identity/10` — one row per registration (closest preceding risk event).
- `entra-apps/01` — high-risk scope families matched by regex (excluding `Mail.ReadBasic`).

### Documentation
- README: playbook index, new query tables, expanded MITRE map, schema notes, contributing checklist; root README kept in sync.
