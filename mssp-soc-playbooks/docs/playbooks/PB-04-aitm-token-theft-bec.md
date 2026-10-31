# PB-04 — AiTM / token theft & business email compromise (BEC)

| Field | Value |
|---|---|
| Playbook ID | PB-04 |
| Version | 1.0 |
| Last reviewed | 2026-10-31 |
| Primary platforms | Microsoft Entra ID (ID Protection), Microsoft Defender XDR, Defender for Cloud Apps, Exchange Online, Microsoft Sentinel |
| MITRE ATT&CK | T1557 — Adversary-in-the-Middle · T1550.001 — Application Access Token · T1539 — Steal Web Session Cookie · T1114.003 — Email Forwarding Rule · T1556.006 — Modify MFA |
| Reference | [Microsoft — Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook) |

---

## 1. Scope

The attacker has a valid **session** (cookie, refresh token or PRT) rather than just the password — typically from an adversary-in-the-middle (AiTM) phishing kit or a device code phishing lure. MFA was satisfied by the victim, so password resets alone are **not** enough.

Common triggers:

- ID Protection: **Anomalous token**, **Unfamiliar sign-in properties**, attacker-in-the-middle detections
- Defender XDR: AiTM / BEC incidents — often tagged **Attack Disruption** (Defender may have already contained or disabled the user)
- Defender for Endpoint: attempted access of the Primary Refresh Token (PRT)
- New inbox rule / forwarding, new MFA method, unusual mass download after a sign-in from a new location

## 2. Prerequisites

- Sign-in logs (interactive and **non-interactive**), AuditLogs and, ideally, `MicrosoftGraphActivityLogs` streaming to Sentinel.
- Defender for Cloud Apps Microsoft 365 connector enabled (populates `CloudAppEvents`).
- Mailbox auditing on (default) — attack disruption for BEC needs MailItemsAccessed, UpdateInboxRules, MoveToDeletedItems, SoftDelete and HardDelete audited.
- Roles to revoke sessions: User Administrator (or a role holding `User.RevokeSessions.All`).

## 3. Severity guide

| Condition | Suggested severity |
|---|---|
| Token anomaly with no follow-on activity, user confirms travel/VPN | Medium (validate, then close) |
| Session replay confirmed from attacker infrastructure | High |
| Inbox rule / forwarding / MFA method added, or outbound phishing sent | Critical |
| Privileged role holder, or financial fraud (payment / invoice thread hijack) | Critical — engage customer immediately |

## 4. Triage (first 15 minutes)

1. If the incident carries the **Attack Disruption** tag, check what Defender already did (contain user, disable user, revoke session) before acting — don't undo it.
2. Identify the first malicious sign-in: `kql/identity/05-targeted-sign-in-forensics-single-user.kql`. Note IP, ASN, user agent, `SessionId`, `UniqueTokenIdentifier`.
3. Look for token replay: successful **non-interactive** sign-ins from the attacker IP with no matching interactive MFA from that IP — `kql/identity/04-aitm-token-replay-non-interactive.kql`.
4. Check the lure: `kql/email/02-url-click-tracking-aitm-link.kql` and `kql/email/04-phishing-delivery-check-before-sign-in.kql`. For device-code lures: `kql/identity/09-device-code-flow-sign-ins.kql`.

## 5. Investigation

| # | Question | How to answer |
|---|---|---|
| 1 | What did the attacker do with the session? | `CloudAppEvents` for the account: `summarize min(Timestamp), max(Timestamp) by IPAddress, CountryCode, City, Application`; filter on attacker IPs. Graph activity by session: join `MicrosoftGraphActivityLogs.SessionId` / `SignInActivityId` to the sign-in `SessionId` / `UniqueTokenIdentifier`. |
| 2 | Mailbox persistence / BEC staging? | `kql/cloud-apps/03-mailbox-forwarding-and-suspicious-rules.kql` — rules that move mail to RSS Subscriptions / Notes / Junk, mark as read, or filter on finance keywords; external forwarding. `kql/cloud-apps/01` / `02` for named users. |
| 3 | Identity persistence? | New MFA method: `kql/identity/10-security-info-registered-after-risk.kql`. New device registrations (AuditLogs entries logged by the Device Registration Service for the user). New OAuth consent: `kql/entra-apps/01-oauth-consent-grant-review.kql`. |
| 4 | Did they send mail? | Outbound/intra-org `EmailEvents` from the user after the compromise time. Internal phishing widens the scope — run PB-01 for those recipients. Financial fraud: identify the hijacked thread and contact the third party out-of-band. |
| 5 | Other victims? | `kql/identity/03-cross-user-pivot-attacker-ips.kql` on all attacker IPs. Note: anomalous-token detections may have no matching `SigninLogs` row — also check `OfficeActivity` / `CloudAppEvents` and `AuditLogs` for the IP. |

## 6. Containment

Order matters — revoke **after** disabling, so the attacker can't refresh in between.

1. **Disable the account** (temporarily): `Update-MgUser -UserId <id> -AccountEnabled:$false`.
2. **Revoke all refresh tokens / session cookies**: `Revoke-MgUserSignInSession -UserId <id>` (Graph: `POST /users/{id}/revokeSignInSessions`) or *Revoke sessions* in the Entra admin center.
   - Access tokens remain valid until they expire (default about one hour). **Continuous Access Evaluation** (Exchange, SharePoint, Teams, Graph) acts on revocation, password change and account disable without waiting for token expiry — Microsoft states event propagation can take up to 15 minutes.
3. **Reset the password** (twice for hybrid accounts).
4. **Remove attacker persistence**: MFA methods they added (Graph `DELETE /users/{id}/authentication/...Methods/{id}`), registered devices (`Update-MgDevice -AccountEnabled:$false`), inbox rules (`Get-InboxRule -IncludeHidden` / `Remove-InboxRule`), forwarding (`Set-Mailbox -ForwardingSmtpAddress $null`), OAuth grants (PB-03).
5. **Confirm user compromised** in ID Protection; block attacker IPs/ASN with a Conditional Access named location (short-term).
6. Re-enable the account once the user has re-registered MFA on a trusted device.

## 7. Eradication & recovery

Recommend to the customer:

- **Phishing-resistant MFA** (passkeys / FIDO2, Windows Hello for Business, certificate-based) — AiTM kits can't relay these.
- Conditional Access requiring **compliant or hybrid-joined devices** for sensitive apps.
- **Token protection** session control (device-bound tokens) where supported.
- **Block device code flow** with the Conditional Access *Authentication flows* condition (report-only first; exclude break-glass accounts, and the Device Registration Service if device registration uses it).
- Sign-in risk / user risk policies; CAE left on (default).

## 8. Closure & reporting

### Ticket note template

**Summary:** Session token stolen via AiTM phishing; attacker replayed the session from external infrastructure.
**Scope:** N accounts; mailbox persistence found (Y/N); outbound mail sent (Y/N).
**Evidence:** Lure delivery/click time, first replayed sign-in (UTC, IP, ASN), persistence created (type and time).
**Actions taken:** Account disabled, sessions revoked, password reset, attacker MFA method/rule/forwarding removed, IPs blocked; account re-enabled after MFA re-registration.
**Recommendations:** Phishing-resistant MFA, device-based Conditional Access, block device code flow, token protection.
**Status:** Closed / Monitoring for 14 days.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/identity/04-aitm-token-replay-non-interactive.kql` | Token replay |
| `kql/identity/05-targeted-sign-in-forensics-single-user.kql` | First malicious sign-in |
| `kql/identity/09-device-code-flow-sign-ins.kql` | Device code phishing |
| `kql/identity/10-security-info-registered-after-risk.kql` | MFA persistence |
| `kql/identity/06-graph-api-service-principal-correlation.kql` | Graph activity correlation |
| `kql/cloud-apps/03-mailbox-forwarding-and-suspicious-rules.kql` | BEC rules and forwarding |

## 10. References

- [Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Automatic attack disruption in Microsoft Defender XDR](https://learn.microsoft.com/defender-xdr/automatic-attack-disruption)
- [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Token protection in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection)
- [Block authentication flows with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)
- [Linkable identifiers (SessionId / UTI) across logs](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-track-linkable-identifiers)
- [Alert grading — suspicious email forwarding](https://learn.microsoft.com/defender-xdr/alert-grading-playbook-email-forwarding)
