# mssp-soc-playbooks

A collection of KQL queries, detection rules, and investigation playbooks built from real-world MSSP SOC operations. All queries are sanitised — client names, UPNs, IPs, and domains have been replaced with generic placeholders. Replace the `// <-- replace` and `// <-- adjust` markers before use.

> **Disclaimer:** All content in this repository is intended for use in authorised security operations environments only. These queries should only be run against tenants and environments where you have explicit permission to do so.

---

## Repository structure

```
mssp-soc-playbooks/
├── README.md
├── kql/
│   ├── identity/               # Sign-in forensics, risky user triage, AiTM detection
│   ├── email/                  # Phishing scoping, URL click tracking, delivery timeline
│   ├── endpoint/               # MDE process/network hunting, LotL, malware detection
│   ├── cloud-apps/             # CloudAppEvents — inbox rules, BEC forensics
│   └── logscale/               # CrowdStrike Falcon LogScale / Humio queries
├── tools/                      # Standalone HTML/PowerShell security tools
└── docs/                       # Investigation runbooks, playbooks, notes
```

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

### Email & phishing

| File | Purpose | Environment |
|---|---|---|
| `01-inbound-email-phishing-campaign-scope.kql` | Campaign scoping by sender, domain, or subject | Defender XDR |
| `02-url-click-tracking-aitm-link.kql` | Click-through detection on known malicious URLs | Defender XDR |
| `03-phishing-email-device-logon-correlation.kql` | Malicious email delivery correlated with device logon | Defender XDR |
| `04-phishing-delivery-check-before-sign-in.kql` | Delivery timeline — confirms initial access vector | Defender XDR |

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
| `10-c2-traffic-blending-auth-endpoint.kql` | High-frequency POST to auth endpoints from non-auth processes | Defender XDR |

### Cloud app events

| File | Purpose | Environment |
|---|---|---|
| `01-inbox-rule-creation-post-compromise.kql` | Inbox rule creation for multiple users — BEC forensics | Defender XDR |
| `02-inbox-rule-single-user-upn-lookup.kql` | Scoped inbox rule check via UPN + ObjectId resolution | Defender XDR |

### CrowdStrike LogScale

| File | Purpose | Environment |
|---|---|---|
| `01-rundll32-non-standard-extension-hunt.lqs` | Falcon hunt — rundll32 loading non-DLL extensions | LogScale |
| `02-rundll32-suspicious-args-sweep.lqs` | Falcon hunt — rundll32 with JS/MSHTML/URL args | LogScale |

---

## MITRE ATT&CK coverage

| Technique | ID | Queries |
|---|---|---|
| Valid Accounts | T1078 / T1078.004 | identity/01, identity/02, identity/03, endpoint/02 |
| Use Alternate Authentication Material | T1550.001 | identity/04, identity/06 |
| Phishing | T1566.001 / T1566.002 | email/01, email/02, email/03, email/04 |
| Email Collection: Forwarding Rule | T1114.003 | cloud-apps/01, cloud-apps/02 |
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
| User display name | `AccountDisplayName` | `UserDisplayName` |
| `arg_max` alternative | `take_any(*) by AccountObjectId` | `arg_max(TimeGenerated, *)` |

> **Note:** `Timestamp` in Defender XDR requires appropriate licensing (MDI / MDA / MDE P2). If you see a schema error on `Timestamp` in IdentityInfo, remove time-based filters and use `take_any(*)` instead of `arg_max`.

---

## Contributing

If you're adding a new query:

1. Follow the header comment format (Title, Purpose, Env, Tables, MITRE)
2. Replace any real client, user, or infrastructure data with generic placeholders
3. Add a `// <-- replace` comment on every line that needs customisation
4. Add the query to the index table in this README

---

## Related tools

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
