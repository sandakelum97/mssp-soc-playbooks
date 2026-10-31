# mssp-soc-playbooks

A collection of KQL queries, detection rules, and investigation playbooks built from real-world MSSP SOC operations. All queries are sanitised — client names, UPNs, IPs, and domains have been replaced with generic placeholders. Replace the `// <-- replace` and `// <-- adjust` markers before use.

> **Disclaimer:** All content in this repository is intended for use in authorised security operations environments only. These queries should only be run against tenants and environments where you have explicit permission to do so.

---

## Repository structure

```
mssp-soc-playbooks/
├── README.md
├── CHANGELOG.md
├── kql/
│   ├── identity/               # Sign-in forensics, risky user triage, AiTM, spray, device code
│   ├── email/                  # Phishing scoping, URL click tracking, delivery & ZAP status
│   ├── endpoint/               # MDE process/network hunting, LotL, ransomware indicators
│   ├── cloud-apps/             # CloudAppEvents — inbox rules, forwarding, BEC forensics
│   ├── entra-apps/             # OAuth consent, app credentials, app permissions
│   └── logscale/               # CrowdStrike Falcon LogScale / Humio queries
└── docs/
    ├── playbooks/              # Incident response playbooks (PB-01 … PB-05) + template
    └── platform-changes.md     # Microsoft platform/schema changes that affect queries
```

---

## Incident response playbooks

Based on Microsoft's published incident response guidance on Microsoft Learn, adapted for MSSP operations (triage → investigation → containment → closure, with a ticket note template) and linked to the queries in this repo.

| Playbook | Scenario | Microsoft Learn basis |
|---|---|---|
| [`PB-01`](docs/playbooks/PB-01-phishing-email-compromise.md) | Phishing email & credential compromise | [Phishing investigation](https://learn.microsoft.com/security/operations/incident-response-playbook-phishing) |
| [`PB-02`](docs/playbooks/PB-02-password-spray.md) | Password spray | [Password spray investigation](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray) |
| [`PB-03`](docs/playbooks/PB-03-malicious-oauth-app-consent.md) | Illicit consent grant & compromised / malicious apps | [App consent grant](https://learn.microsoft.com/security/operations/incident-response-playbook-app-consent) · [Compromised & malicious apps](https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app) |
| [`PB-04`](docs/playbooks/PB-04-aitm-token-theft-bec.md) | AiTM / token theft & BEC | [Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook) |
| [`PB-05`](docs/playbooks/PB-05-ransomware-pre-encryption.md) | Human-operated ransomware — pre-encryption | [Human-operated ransomware](https://learn.microsoft.com/security/ransomware/human-operated-ransomware) · [Hunt for ransomware](https://learn.microsoft.com/defender-xdr/advanced-hunting-find-ransomware) |
| [`PB-00`](docs/playbooks/00-playbook-template.md) | Template for new playbooks | — |

---

## KQL query index

### Identity & sign-ins

| File | Purpose | Environment |
|---|---|---|
| `01-risky-user-account-status-lookup.kql` | Bulk IdentityInfo lookup — enabled status, UPN, ObjectId | Defender XDR |
| `02-risky-sign-ins-high-risk-filter.kql` | High-risk sign-in events for named users | Sentinel |
| `03-cross-user-pivot-attacker-ips.kql` | Lateral spread check — other users on attacker IPs | Sentinel |
| `04-aitm-token-replay-non-interactive.kql` | Non-interactive sign-ins — token replay detection | Sentinel |
| `05-targeted-sign-in-forensics-single-user.kql` | Single-user sign-in deep dive with CA and risk metadata | Sentinel |
| `06-graph-api-service-principal-correlation.kql` | Graph API calls correlated with service principal sign-ins | Sentinel |
| `07-password-spray-source-ips.kql` | Spray source IPs + accounts with a valid password (success / MFA interrupt) | Sentinel |
| `08-legacy-auth-sign-ins.kql` | Legacy-protocol sign-ins (no MFA possible) — scope a block policy | Sentinel |
| `09-device-code-flow-sign-ins.kql` | Device code flow sign-ins — device code phishing check | Sentinel |
| `10-security-info-registered-after-risk.kql` | MFA method registered within 24h of a risk detection | Sentinel |

### Email & phishing

| File | Purpose | Environment |
|---|---|---|
| `01-inbound-email-phishing-campaign-scope.kql` | Campaign scoping by sender, domain, or subject | Defender XDR |
| `02-url-click-tracking-aitm-link.kql` | Click-through detection on known malicious URLs | Defender XDR |
| `03-phishing-email-device-logon-correlation.kql` | Malicious email delivery correlated with device logon | Defender XDR |
| `04-phishing-delivery-check-before-sign-in.kql` | Delivery timeline — confirms initial access vector | Defender XDR |
| `05-post-delivery-zap-and-remediation-status.kql` | ZAP / manual remediation status — copies still needing removal | Defender XDR |

### Endpoint

| File | Purpose | Environment |
|---|---|---|
| `01-endpoint-dns-ioc-domain-lookup.kql` | IOC domain sweep across all MDE-enrolled endpoints | Defender XDR |
| `02-last-device-logon.kql` | Last interactive logon on a specific device | Defender XDR |
| `03-rundll32-suspicious-arguments.kql` | rundll32 JS/MSHTML/URL proxy execution detection | Defender XDR |
| `04-rundll32-non-standard-path.kql` | rundll32 running outside System32/SysWOW64 | Defender XDR |
| `05-office-spawning-rundll32.kql` | Office app spawning rundll32 as child process | Defender XDR |
| `06-rundll32-external-network-connections.kql` | rundll32 making outbound connections to public IPs | Defender XDR |
| `07-non-standard-extension-dll-execution.kql` | rundll32 loading .rfg/.dat/.cfg — RAT staging pattern | Defender XDR |
| `08-ping-sleep-directory-wipe.kql` | Ping sleep + rd /s /q — sandbox evasion + cleanup chain | Defender XDR |
| `09-slui-uac-bypass.kql` | slui.exe -Embedding UAC bypass detection | Defender XDR |
| `10-c2-traffic-blending-auth-endpoint.kql` | High-frequency connections to Microsoft auth endpoints from unexpected processes | Defender XDR |
| `11-ransomware-pre-encryption-indicators.kql` | Shadow copy / backup deletion, boot recovery off, log clearing — by device | Defender XDR |

### Cloud app events

| File | Purpose | Environment |
|---|---|---|
| `01-inbox-rule-creation-post-compromise.kql` | Inbox rule creation for multiple users — BEC forensics | Defender XDR |
| `02-inbox-rule-single-user-upn-lookup.kql` | Scoped inbox rule check via UPN + ObjectId resolution | Defender XDR |
| `03-mailbox-forwarding-and-suspicious-rules.kql` | Tenant-wide forwarding / rule parameters — external forward, hide, delete, keywords | Defender XDR |

### Entra applications

| File | Purpose | Environment |
|---|---|---|
| `01-oauth-consent-grant-review.kql` | Consent to application — admin vs user, high-risk scopes flagged | Sentinel |
| `02-app-credential-added.kql` | Secrets / certificates added to apps or service principals | Sentinel |
| `03-app-role-or-delegated-grant-added.kql` | New app role assignments and delegated permission grants | Sentinel |

### CrowdStrike LogScale

| File | Purpose | Environment |
|---|---|---|
| `01-rundll32-non-standard-extension-hunt.lqs` | Falcon hunt — rundll32 loading non-DLL extensions | LogScale |
| `02-rundll32-suspicious-args-sweep.lqs` | Falcon hunt — rundll32 with JS/MSHTML/URL args | LogScale |

---

## MITRE ATT&CK coverage

| Technique | ID | Queries |
|---|---|---|
| Valid Accounts | T1078 / T1078.004 | identity/01, identity/02, identity/03, identity/08, endpoint/02 |
| Brute Force: Password Spraying | T1110.003 | identity/07 |
| Use Alternate Authentication Material | T1550.001 | identity/04, identity/06 |
| Steal Application Access Token | T1528 | identity/09, entra-apps/01 |
| Account Manipulation: Additional Cloud Credentials | T1098.001 | entra-apps/02 |
| Account Manipulation: Additional Cloud Roles | T1098.003 | entra-apps/03 |
| Modify Authentication Process: MFA | T1556.006 | identity/10 |
| Phishing | T1566.001 / T1566.002 | email/01–05, identity/09 |
| Email Collection: Forwarding Rule | T1114.003 | cloud-apps/01–03 |
| Hide Artifacts: Email Hiding Rules | T1564.008 | cloud-apps/03 |
| Inhibit System Recovery | T1490 | endpoint/11 |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | endpoint/11 |
| System Binary Proxy Execution: Rundll32 | T1218.011 | endpoint/03–07, logscale/01–02 |
| Masquerading: Double File Extension | T1036.007 | endpoint/07 |
| Application Layer Protocol | T1071.001 | endpoint/01, endpoint/06, endpoint/10 |
| Bypass User Account Control | T1548.002 | endpoint/09 |
| Sandbox Evasion: Time Based | T1497.003 | endpoint/08 |
| Indicator Removal: File Deletion | T1070.004 | endpoint/08 |

---

## How to use these queries

### Microsoft Defender XDR (Advanced Hunting)
1. Go to [security.microsoft.com](https://security.microsoft.com) → **Hunting** → **Advanced hunting**
2. Paste the query into the editor
3. Replace all `// <-- replace` placeholder values with your investigation data
4. Set an appropriate time range
5. Run and pivot from results

### Microsoft Sentinel (Log Analytics)
1. Go to your Sentinel workspace → **Logs**
2. Paste the query into the editor
3. Replace placeholders and adjust the time range
4. For scheduled detection rules: **Analytics** → **Create** → **Scheduled query rule**

### CrowdStrike Falcon LogScale
1. Go to Falcon console → **Investigate** → **Event Search**
2. Paste the `.lqs` query
3. Set the time range and run

---

## Schema notes

A few schema differences to be aware of when switching environments:

| Column | Defender XDR (Advanced Hunting) | Sentinel (Log Analytics) |
|---|---|---|
| Time column | `Timestamp` | `TimeGenerated` |
| UPN column in IdentityInfo | `AccountUpn` | `AccountUpn` |
| User display name (sign-in tables) | `AccountDisplayName` (EntraIdSignInEvents) | `UserDisplayName` (SigninLogs) |
| Sign-in result | `ErrorCode` (int, EntraIdSignInEvents) | `ResultType` (**string** — compare with `"0"`) |
| `arg_max` alternative | `take_any(*) by AccountObjectId` | `arg_max(TimeGenerated, *)` |

> **Note:** In Defender XDR `IdentityInfo`, the `Timestamp` column is only available to tenants with Defender for Identity, Defender for Cloud Apps or Defender for Endpoint P2 licensing. If you see a schema error on `Timestamp` in IdentityInfo, remove time-based filters and use `summarize take_any(*) by ...` instead of `arg_max`.

See [`docs/platform-changes.md`](docs/platform-changes.md) for recent Microsoft changes (Sentinel moving to the Defender portal after 31 March 2027, `EntraIdSignInEvents`, `Get-MessageTraceV2`) and the schema gotchas fixed in this repo.

---

## Contributing

If you're adding a new query:

1. Follow the header comment format (Title, Purpose, Env, Tables, MITRE, and `Ref` — the Microsoft Learn or vendor page the logic is based on)
2. Replace any real client, user, or infrastructure data with generic placeholders
3. Add a `// <-- replace` comment on every line that needs customisation
4. Add the query to the index table in this README
5. Verify table and column names against the current schema reference ([Defender XDR](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables), [Azure Monitor tables](https://learn.microsoft.com/azure/azure-monitor/reference/tables-index)) and run it in a lab tenant before committing
6. New playbooks: copy [`docs/playbooks/00-playbook-template.md`](docs/playbooks/00-playbook-template.md)
7. Record the change in [`CHANGELOG.md`](CHANGELOG.md)

---

## Related tools

> These tools are not published in this repository yet.

| Tool | Description |
|---|---|
| `tools/defender-tvm-rmm-crosscheck.html` | Cross-reference Defender TVM CSV exports against ConnectWise RMM device lists |
| `tools/powershell-script-analyzer.html` | React-based PowerShell script security analyser |
| `tools/ad-investigation-wizard.html` | Interactive AD investigation playbook with SID auto-population and confidence scoring |

---

## Author

**Tharaka D.**  
Security Engineer — MSSP  
[GitHub](https://github.com/sandakelum97) · [Portfolio](https://sandakelum97.github.io)

---

*Built from real SOC operations. All client data sanitised. For authorised use only.*
