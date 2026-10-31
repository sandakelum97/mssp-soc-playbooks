# PB-02 — Password spray

| Field | Value |
|---|---|
| Playbook ID | PB-02 |
| Version | 1.0 |
| Last reviewed | 2026-10-31 |
| Primary platforms | Microsoft Entra ID (ID Protection), Microsoft Sentinel, AD FS (federated tenants) |
| MITRE ATT&CK | T1110.003 — Brute Force: Password Spraying · T1078.004 — Cloud Accounts |
| Reference | [Microsoft — Password spray investigation playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray) |

---

## 1. Scope

Triggered by an ID Protection **Password spray** risk detection, a Sentinel spray analytic, a spike of failed sign-ins across many accounts, or users reporting unexpected MFA prompts.

Important: ID Protection's *Password spray* detection (riskEventType `passwordSpray`, Entra ID P2) only fires when the attacker **successfully validates a password**. A spray that only produced failures will not create that detection — hunt for it with `kql/identity/07-password-spray-source-ips.kql`.

## 2. Prerequisites

- Know the authentication model per domain (`Get-MgDomain`):
  - **Managed** (cloud-only, PHS, PTA): successes and failures are both in Entra sign-in logs.
  - **Federated** (AD FS): failures are logged at AD FS, not in Entra. AD FS auditing should be set to *Verbose* and "Application Generated" success/failure auditing enabled; Entra Connect Health for AD FS provides the Risky IP report.
- Sign-in logs streaming to Sentinel (portal retention is short).
- Smart lockout is always on. Defaults: lockout after **10** failed attempts (Azure public cloud), first lockout **60 seconds**, increasing on repeat. It ignores repeats of the same wrong password, and tracks familiar and unfamiliar locations separately.

## 3. Key result codes

| ResultType | Meaning | Use |
|---|---|---|
| `0` | Success | **Highest priority** if from a spray IP |
| `50126` | Invalid username or password | Core spray failure |
| `50053` | Account locked (smart lockout) or sign-in from a known malicious IP blocked | Spray failure / lockout |
| `50074`, `50076` | Strong auth (MFA) required | Password was correct — treat as compromised password |
| `50079` | User must register security info | Password correct, no MFA registered — urgent |
| `53003` | Blocked by Conditional Access | Password may be correct — review |
| `50057` | Account disabled | Context only |

## 4. Triage (first 15 minutes)

1. Run `kql/identity/07-password-spray-source-ips.kql` for the alert window. It lists spray IPs, the number of accounts targeted, and any accounts that **succeeded** or reached **MFA** from those IPs.
2. Prioritise accounts in this order: success from spray IP → MFA interrupted (correct password) → CA-blocked → failures only.
3. Check for legacy authentication use by targeted accounts — legacy protocols can't do MFA: `kql/identity/08-legacy-auth-sign-ins.kql`.

## 5. Investigation

| # | Question | How to answer |
|---|---|---|
| 1 | Is it a spray or a single-account brute force? | Spray = many users, few attempts each, from one IP/ASN or a rotating set. Look for alphabetical (address-book order) targeting, a single user agent, and regular timing ("low and slow"). |
| 2 | Which passwords were correct? | Any `0`, `50074`, `50076`, `50079`, `53003` result from the spray IPs. These users need a password reset regardless of whether MFA stopped the attacker. |
| 3 | Did a compromised account do anything? | `kql/identity/05-targeted-sign-in-forensics-single-user.kql` and `kql/identity/04-aitm-token-replay-non-interactive.kql`; mailbox rules/forwarding `kql/cloud-apps/03-mailbox-forwarding-and-suspicious-rules.kql`; new MFA methods `kql/identity/10-security-info-registered-after-risk.kql`. |
| 4 | Are other users signing in from the same IPs? | `kql/identity/03-cross-user-pivot-attacker-ips.kql` |
| 5 | Federated tenant? | AD FS events 411 / 342 (failed auth), 516 (extranet lockout), 412 / 1202 (success), 1203 (fresh credential failure). |

## 6. Containment

1. **Accounts with a correct password**: reset password, revoke sessions (`Revoke-MgUserSignInSession`), and confirm compromised in ID Protection if any successful sign-in occurred.
2. **Block the source**: Conditional Access named location (IP ranges) + block policy for all resources, or at the firewall / `Set-AdfsProperties -AddBannedIps` for AD FS. Expect the attacker to rotate IPs — blocking is a short-term measure.
3. **Block legacy authentication** with Conditional Access (check business impact using query 08 first).

## 7. Eradication & recovery

- Enforce MFA for all users (Conditional Access); enable user-risk and sign-in-risk policies.
- Turn on Entra Password Protection with a custom banned-password list (company name, products, locations, seasons).
- For AD FS: enable Extranet Smart Lockout; consider moving to cloud authentication.

## 8. Closure & reporting

### Ticket note template

**Summary:** Password spray from N source IPs targeting N accounts over HH:MM (UTC).
**Scope:** N accounts targeted; N with valid password (N stopped by MFA, N successful sign-ins).
**Evidence:** Source IPs/ASN, time window, result-code breakdown.
**Actions taken:** Passwords reset and sessions revoked for N accounts; IP ranges blocked via Conditional Access named location.
**Recommendations:** MFA for all users, block legacy auth, banned-password list.
**Status:** Closed / Monitoring.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/identity/07-password-spray-source-ips.kql` | Spray IPs and accounts with valid passwords |
| `kql/identity/08-legacy-auth-sign-ins.kql` | Legacy auth exposure |
| `kql/identity/03-cross-user-pivot-attacker-ips.kql` | Pivot on attacker IPs |
| `kql/identity/05`, `kql/identity/10`, `kql/cloud-apps/03` | Post-compromise activity |

## 10. References

- [Password spray investigation playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray)
- [Smart lockout](https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout)
- [ID Protection risk detection types](https://learn.microsoft.com/entra/id-protection/concept-risk-detection-types)
- [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)
- [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication)
