# PB-05 — Human-operated ransomware: pre-encryption response

| Field | Value |
|---|---|
| Playbook ID | PB-05 |
| Version | 1.0 |
| Last reviewed | 2026-10-31 |
| Primary platforms | Microsoft Defender for Endpoint, Microsoft Defender XDR, Defender for Identity, Microsoft Sentinel |
| MITRE ATT&CK | T1490 — Inhibit System Recovery · T1070.001 — Clear Windows Event Logs · T1562.001 — Impair Defenses · T1486 — Data Encrypted for Impact |
| Reference | [Microsoft — Human-operated ransomware](https://learn.microsoft.com/security/ransomware/human-operated-ransomware) · [Hunt for ransomware](https://learn.microsoft.com/defender-xdr/advanced-hunting-find-ransomware) |

---

## 1. Scope

Human-operated ransomware is hands-on-keyboard: the attacker steals credentials, moves laterally, disables defences and destroys backups **before** encrypting. This playbook covers the window where those preparation steps are detected — the goal is to stop encryption, not to recover from it. If encryption has already started, escalate to the customer's major-incident / DFIR process immediately and preserve evidence.

Triggers: Defender XDR ransomware or "human-operated" incidents (often with **Attack Disruption** — contain device / contain user), shadow-copy deletion, tampering alerts, mass service stops, or hits from `kql/endpoint/11-ransomware-pre-encryption-indicators.kql`.

## 2. Prerequisites

- Defender for Endpoint in active (block) mode with **tamper protection** on; devices onboarded.
- Agreed emergency authority in the MSSP contract to isolate devices and disable accounts **without waiting for approval** when ransomware preparation is confirmed. Agree this in advance — minutes matter.
- Out-of-band contact list for the customer (phone), since email/Teams may be compromised.

## 3. Severity guide

Any confirmed recovery-inhibition command run by a non-backup process is **Critical**. Multiple techniques on one device within an hour, or the same activity across several devices, means an active operation.

## 4. Triage (first 15 minutes)

1. Run `kql/endpoint/11-ransomware-pre-encryption-indicators.kql` — which devices, which techniques, which account, parent process.
2. Rule out legitimate backup software (check the parent process and the customer's backup product). Shadow copy *deletion* by an admin shell, PsExec, WMI or a script host is not normal.
3. If not legitimate: **contain now** (section 6) and investigate in parallel.

## 5. Investigation

| # | Question | How to answer |
|---|---|---|
| 1 | Which account is running it, and from where? | `AccountName` / `InitiatingProcessAccountName` in query 11; logons to the device: `kql/endpoint/02-last-device-logon.kql`; RDP: `DeviceLogonEvents` with `LogonType == "RemoteInteractive"`. |
| 2 | How far has it spread? | Same commands on other devices (query 11 across the estate); remote execution — `DeviceProcessEvents` for `psexesvc.exe`, `wmiprvse.exe` children, and scheduled tasks/services created around the same time. |
| 3 | Were defences tampered with? | Defender tampering alerts; `DeviceEvents` for antivirus configuration changes; mass `sc config ... disabled`, `net stop`, `taskkill` against security/backup services. |
| 4 | Was data exfiltrated first? | Large outbound transfers in `DeviceNetworkEvents`; archive tools (7z, rar, WinRAR) and cloud sync / transfer tools (rclone etc.) in `DeviceProcessEvents`. |
| 5 | How did they get in? | Work backwards from the first malicious logon: phishing (PB-01), compromised remote access (VPN/RDP), exploited internet-facing service, or a valid account (PB-02 / PB-04). |

## 6. Containment

1. **Isolate affected devices** in Defender for Endpoint (full isolation). Keep them powered on — memory and logs are evidence.
2. **Contain / disable the account(s)** being used, revoke their sessions (`Revoke-MgUserSignInSession`), and reset passwords. For on-premises AD accounts, disable in AD as well; if a domain admin is involved, plan a krbtgt reset with the customer's AD team (two resets, spaced by replication / ticket lifetime).
3. **Protect backups**: confirm with the customer that backup consoles and repositories are intact and isolated; change backup admin credentials.
4. Block observed IOCs (hashes, IPs, domains) as Defender custom indicators.

## 7. Eradication & recovery

- Remove persistence (services, scheduled tasks, run keys, new local admins) on every affected device; reimage where integrity is in doubt.
- Restore only from backups verified clean and older than the initial access time.
- Recommend: attack surface reduction rules (including the advanced ransomware protection rule), controlled folder access for high-value data, LAPS for local admin passwords, MFA for remote access and admins, removal of internet-exposed RDP.

## 8. Closure & reporting

### Ticket note template

**Summary:** Ransomware preparation activity (shadow copy / backup deletion) detected on N devices before encryption.
**Scope:** N devices, N accounts; encryption observed (Y/N); exfiltration indicators (Y/N).
**Evidence:** First malicious command (UTC, device, account, parent process); techniques observed.
**Actions taken:** Devices isolated at HH:MM UTC; accounts disabled and sessions revoked; IOCs blocked; backups confirmed isolated.
**Recommendations:** As per section 7.
**Status:** Escalated to customer major incident / Monitoring.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/endpoint/11-ransomware-pre-encryption-indicators.kql` | Recovery-inhibition techniques by device |
| `kql/endpoint/02-last-device-logon.kql` | Who is on the device |
| `kql/endpoint/08-ping-sleep-directory-wipe.kql` | Stager clean-up patterns |
| `kql/endpoint/06-rundll32-external-network-connections.kql` | Possible C2 from LOLBins |

## 10. References

- [Human-operated ransomware](https://learn.microsoft.com/security/ransomware/human-operated-ransomware)
- [Hunt for ransomware with advanced hunting](https://learn.microsoft.com/defender-xdr/advanced-hunting-find-ransomware)
- [Detect and respond to ransomware attacks with Defender XDR](https://learn.microsoft.com/defender-xdr/playbook-detecting-ransomware-m365-defender)
- [Automatic attack disruption](https://learn.microsoft.com/defender-xdr/automatic-attack-disruption)
- [Protect against ransomware (rapid protection)](https://learn.microsoft.com/security/ransomware/protect-against-ransomware)
