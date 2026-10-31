# PB-01 — Phishing email & credential compromise

| Field | Value |
|---|---|
| Playbook ID | PB-01 |
| Version | 1.0 |
| Last reviewed | 2026-10-31 |
| Primary platforms | Microsoft Defender XDR (Defender for Office 365, Defender for Endpoint), Microsoft Entra ID, Exchange Online, Microsoft Sentinel |
| MITRE ATT&CK | T1566.001, T1566.002 (Phishing) · T1078.004 (Cloud Accounts) · T1114.003 (Email Forwarding Rule) |
| Reference | [Microsoft — Phishing investigation playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-phishing) |

---

## 1. Scope

Use when a user reports a phishing email, Defender for Office 365 raises a phishing / malicious URL click alert, or ZAP removes a message after delivery. If sign-in evidence shows a session token was stolen (AiTM), continue in **PB-04**. If an OAuth app was consented to, continue in **PB-03**.

## 2. Prerequisites

- **Mailbox auditing** is on by default for every organisation. Confirm it hasn't been disabled: `Get-OrganizationConfig | Format-List AuditDisabled` should return `False`.
- **Unified audit log (Audit Standard)**: retention is 180 days for records created on or after 17 October 2023 (longer with Audit Premium / add-ons). Exchange admin events can take up to ~30 minutes to appear.
- **Entra sign-in logs** in the portal are short-lived (30 days with P1/P2) — make sure they stream to Sentinel / Log Analytics.
- **Message trace**: 90-day retention. Use `Get-MessageTraceV2` (the older `Get-MessageTrace` is being deprecated); it searches up to 10 days per query.
- **Roles**: Security Reader is enough to investigate. Email remediation (soft/hard delete) needs the **Search and Purge** role. Account containment needs User Administrator or equivalent — follow the customer's approval matrix.
- Note: `Search-Mailbox` is no longer available in Exchange Online — use Content search / `New-ComplianceSearch` or Threat Explorer.

## 3. Severity guide

| Condition | Suggested severity |
|---|---|
| Reported email, not clicked, no credentials entered, ZAP/remediation complete | Low |
| Link clicked (or click-through past Safe Links warning) but no suspicious sign-in | Medium |
| Successful sign-in from an unfamiliar IP / risky sign-in after the click | High |
| Privileged account, forwarding rule created, or internal phishing sent from the account | Critical |

## 4. Triage (first 15 minutes)

1. **Get the message identifiers** — sender, subject, `NetworkMessageId`, delivery time — from the alert or the user's report.
2. **Scope the campaign** — who else received it and where it landed.
   `kql/email/01-inbound-email-phishing-campaign-scope.kql`
3. **Check clicks** — who clicked, and whether anyone clicked through a Safe Links warning (`IsClickedThrough`).
   `kql/email/02-url-click-tracking-aitm-link.kql`
4. **Check removal status** — did ZAP or remediation already pull every copy?
   `kql/email/05-post-delivery-zap-and-remediation-status.kql`
5. **Decide**: no clicks + all copies removed → remediate and close as Low. Any click or any risky sign-in → continue.

## 5. Investigation

| # | Question | How to answer |
|---|---|---|
| 1 | Is the email malicious? | Review headers: SPF, DKIM, DMARC / CompAuth results, originating IP, reply-to mismatch. Check URL/file reputation in Defender (URL and file pages) and Threat Explorer. |
| 2 | Was the payload executed on an endpoint? | Device timeline in Defender for Endpoint; DNS/connection to the IOC domain: `kql/endpoint/01-endpoint-dns-ioc-domain-lookup.kql`. Attachment lures: `kql/email/03-phishing-email-device-logon-correlation.kql`, `kql/endpoint/05-office-spawning-rundll32.kql`. |
| 3 | Were credentials used after the click? | `kql/email/04-phishing-delivery-check-before-sign-in.kql` to fix the timeline, then `kql/identity/05-targeted-sign-in-forensics-single-user.kql` and `kql/identity/02-risky-sign-ins-high-risk-filter.kql`. Look for new IP / ASN / country / user agent, MFA satisfied by "token" rather than by a fresh prompt, and non-interactive sign-ins from the attacker IP (`kql/identity/04-aitm-token-replay-non-interactive.kql`). |
| 4 | Did the attacker reach other users? | `kql/identity/03-cross-user-pivot-attacker-ips.kql` |
| 5 | Persistence in the mailbox? | Forwarding and rules: `kql/cloud-apps/03-mailbox-forwarding-and-suspicious-rules.kql`, `kql/cloud-apps/02-inbox-rule-single-user-upn-lookup.kql`. Also check mailbox delegates (`Get-MailboxPermission`) and removed inbox rules (`Remove-InboxRule` in the audit log). |
| 6 | Persistence in the identity? | New MFA methods after the risk: `kql/identity/10-security-info-registered-after-risk.kql`. New OAuth consents: `kql/entra-apps/01-oauth-consent-grant-review.kql`. |
| 7 | Did the attacker send mail as the user? | Outbound `EmailEvents` from the user after the compromise time (`EmailDirection == "Outbound"` / `"Intra-org"`). Internal phishing increases scope — return to step 2 for those recipients. |

## 6. Containment

Get customer approval where the MSSP agreement requires it.

1. **Remove the email** from all mailboxes: Threat Explorer / advanced hunting → *Take actions* → **Soft delete** (recoverable) or **Hard delete**. Batches of ≤ 50,000 are recommended.
2. **Block the indicators**: sender / domain / URL / file in the Tenant Allow/Block List.
3. **For each compromised account** (credentials entered or suspicious sign-in):
   - Reset the password (twice for hybrid accounts, so the change syncs through).
   - **Revoke sessions**: Entra admin center → user → *Revoke sessions*, or `Revoke-MgUserSignInSession -UserId <id>`. Existing access tokens stay valid until they expire (about one hour), so watch for activity after revocation.
   - Confirm risk in ID Protection (*Confirm user compromised*) so risk policies apply.
   - Remove attacker-added MFA methods, inbox rules, forwarding and delegates found in step 5–6.
4. If an endpoint ran the payload: **isolate the device** in Defender for Endpoint and run a full scan / collect an investigation package.

## 7. Eradication & recovery

- Remove forwarding: `Set-Mailbox <identity> -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false`.
- Remove malicious rules (`Remove-InboxRule`; use `Get-InboxRule -IncludeHidden` to see hidden rules).
- Re-enable the account only after the above is complete and the user has re-registered MFA on a trusted device.
- Notify recipients of any internal phishing sent from the account.

## 8. Closure & reporting

- Set the incident classification (True positive — Phishing / Malicious user activity) in Defender XDR.
- Recommendations to the customer, as applicable: phishing-resistant MFA for admins, Safe Links / Safe Attachments policies, block auto-forwarding to external domains (outbound spam policy), user reporting button, attack simulation training.

### Ticket note template

**Summary:** Phishing email from an external sender delivered to N recipients; N clicked; N submitted credentials.
**Scope:** N mailboxes received, N users clicked, N accounts compromised (names in ticket only).
**Evidence:** Delivery time (UTC), click time(s), first suspicious sign-in (UTC, IP, country).
**Actions taken:** Email soft/hard deleted from N mailboxes; sender and URL blocked; passwords reset and sessions revoked for affected accounts; malicious inbox rule removed.
**Recommendations:** As per section 8.
**Status:** Closed / Monitoring for 7 days.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/email/01-inbound-email-phishing-campaign-scope.kql` | Campaign recipients and delivery location |
| `kql/email/02-url-click-tracking-aitm-link.kql` | Clicks and click-through |
| `kql/email/05-post-delivery-zap-and-remediation-status.kql` | Copies still needing removal |
| `kql/email/04-phishing-delivery-check-before-sign-in.kql` | Initial access timeline |
| `kql/identity/02`, `03`, `04`, `05` | Sign-in forensics and pivot |
| `kql/identity/10-security-info-registered-after-risk.kql` | MFA persistence |
| `kql/cloud-apps/01`, `02`, `03` | Mailbox rules and forwarding |

## 10. References

- [Phishing investigation playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-phishing)
- [Remediate malicious email delivered in Office 365](https://learn.microsoft.com/defender-office-365/remediate-malicious-email-delivered-office-365)
- [EmailPostDeliveryEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailpostdeliveryevents-table)
- [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Manage mailbox auditing](https://learn.microsoft.com/purview/audit-mailboxes)
- [Message trace FAQ](https://learn.microsoft.com/exchange/monitoring/trace-an-email-message/message-trace-faq)
