# PB-03 — Illicit consent grant & compromised / malicious applications

| Field | Value |
|---|---|
| Playbook ID | PB-03 |
| Version | 1.0 |
| Last reviewed | 2026-10-31 |
| Primary platforms | Microsoft Entra ID, Microsoft Defender for Cloud Apps (App governance), Microsoft Sentinel |
| MITRE ATT&CK | T1528 — Steal Application Access Token · T1098.001 — Additional Cloud Credentials · T1098.003 — Additional Cloud Roles |
| Reference | [Microsoft — App consent grant playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-app-consent) · [Compromised and malicious applications playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app) |

---

## 1. Scope

Two related scenarios:

- **Consent phishing** — a user (or admin) is tricked into consenting to an attacker's multi-tenant app, which then reads mail/files through Microsoft Graph without needing the password.
- **Compromised application** — an attacker adds credentials, permissions or redirect URIs to an existing app registration or service principal in the tenant for persistence.

Triggers: App governance / Defender for Cloud Apps OAuth alerts, ID Protection risky workload identity, "Consent to application" with *Risky application detected*, users reporting an unexpected permission prompt, or findings from PB-01 / PB-04.

## 2. Prerequisites

- Entra audit logs streaming to Sentinel (`AuditLogs`). The Entra portal's user → Applications view only shows recent admin consents, so use logs or Graph for the full history.
- Audit entries can take from 30 minutes up to 24 hours to appear.
- **Consent types**: `AllPrincipals` = admin consented for the whole tenant; `Principal` = one user consented for themselves.
- Roles: Security Reader to investigate; Application Administrator / Cloud Application Administrator to disable apps and remove grants; Privileged Role Administrator to change consent settings.
- Entra ID P2 for risky workload identities; Defender for Cloud Apps for App governance.

## 3. Severity guide

| Condition | Suggested severity |
|---|---|
| User consent, low-impact scopes only (User.Read, openid, profile, email, offline_access) | Low |
| User consent to Mail.*, Files.*, Contacts.*, MailboxSettings.*, People.*, Notes.* | High |
| Admin (`AllPrincipals`) consent, application permissions, or any `*.ReadWrite.All` / `RoleManagement.ReadWrite.Directory` | Critical |
| New credential on an existing app not made by its owner | High |

> Microsoft notes that combinations of Mail, Contacts, MailboxSettings, People, Files and Notes scopes appear in the vast majority of consent-phishing attacks.

## 4. Triage (first 15 minutes)

1. Run `kql/entra-apps/01-oauth-consent-grant-review.kql` — who consented, from which IP, admin vs user, and whether high-risk scopes were granted.
2. Check the app: publisher verified? Display name misspelled or generic? Reply URL / redirect domain recently registered? Registered in an unknown or new tenant?
3. Was the consenting user's sign-in suspicious at that time? (`kql/identity/05-targeted-sign-in-forensics-single-user.kql`)

## 5. Investigation

| # | Question | How to answer |
|---|---|---|
| 1 | Which users granted the app access? | Query 01 grouped by `AppSpId`; Entra admin center → Enterprise applications → app → *Permissions* and *Users and groups*. |
| 2 | What did the app do with the access? | Graph calls by the app: `MicrosoftGraphActivityLogs` filtered on `AppId` / `ServicePrincipalId` (`kql/identity/06-graph-api-service-principal-correlation.kql` for service principal tokens). Mailbox access: `MailItemsAccessed` in the audit log; `CloudAppEvents` filtered on `OAuthAppId`. |
| 3 | Were credentials added to apps or service principals? | `kql/entra-apps/02-app-credential-added.kql` — confirm each change with the app owner. |
| 4 | Were new permissions / app roles granted? | `kql/entra-apps/03-app-role-or-delegated-grant-added.kql` — alert-worthy when the target is Microsoft Graph or Exchange Online. |
| 5 | Did the app's service principal sign in from unusual places? | `AADServicePrincipalSignInLogs` (location, IP, failures, frequency); ID Protection → risky workload identities. |
| 6 | Other configuration changes? | AuditLogs "Update application" / "Update service principal" — redirect URIs, sign-out URL, owners ("Add owner to application"). |

## 6. Containment

1. **Disable the app — don't delete it first.** Entra admin center → Enterprise applications → app → Properties → *Enabled for users to sign in?* = **No**, or:
   `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false`
   A disabled app can't get new tokens and users can't consent to it again. Deleting the service principal lets it come back if another user re-consents.
2. **Remove the grants**: delegated grants with `Remove-MgOauth2PermissionGrant`; app role assignments with `Remove-MgServicePrincipalAppRoleAssignedTo`. Already-issued access tokens stay valid until they expire.
3. **Compromised in-tenant app**: remove attacker-added secrets/certificates (Graph `removePassword` / `removeKey` on both the application and the service principal), then add a new credential for the legitimate owner. Rotate any Key Vault secrets the app could read.
4. If the consenting user's account was also compromised, run PB-04 containment (reset, revoke sessions).

## 7. Eradication & recovery

- Watch for the app being re-enabled ("Update service principal" with AccountEnabled = true) or restored ("Restore service principal" / "Add service principal").
- Report malicious multi-tenant apps to Microsoft.
- Hardening (recommend to the customer):
  - User consent setting: **Allow user consent for apps from verified publishers, for selected permissions** (low-impact permissions classified first), or no user consent.
  - Enable the **admin consent workflow** so users can request instead of being blocked silently.
  - Assign an owner to every enterprise app; review consented apps on a schedule.
  - Enable App governance OAuth app policies (e.g. overprivileged app, new highly privileged app, unusual addition of credentials).
  - Conditional Access for risky workload identities (single-tenant apps).

## 8. Closure & reporting

### Ticket note template

**Summary:** User/admin consent granted to an unverified application requesting mail/file access.
**Scope:** N users consented; consent type (Principal / AllPrincipals); scopes granted.
**Evidence:** Consent time (UTC), consenting IP, app ID and publisher details, Graph activity observed.
**Actions taken:** App disabled for sign-in; delegated grants removed; affected users' sessions revoked.
**Recommendations:** Restrict user consent to verified publishers + low-impact permissions; enable admin consent workflow.
**Status:** Closed / Monitoring for re-enable.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/entra-apps/01-oauth-consent-grant-review.kql` | Consent events and risky scopes |
| `kql/entra-apps/02-app-credential-added.kql` | Credential persistence on apps |
| `kql/entra-apps/03-app-role-or-delegated-grant-added.kql` | New permissions / app roles |
| `kql/identity/06-graph-api-service-principal-correlation.kql` | What the app did in Graph |

## 10. References

- [App consent grant investigation](https://learn.microsoft.com/security/operations/incident-response-playbook-app-consent)
- [Compromised and malicious applications investigation](https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app)
- [Microsoft Entra audit log activities](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities)
- [Entra security operations guide for applications](https://learn.microsoft.com/entra/architecture/security-operations-applications)
- [Configure user consent settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
- [Grant and revoke API permissions with Microsoft Graph PowerShell](https://learn.microsoft.com/powershell/microsoftgraph/how-to-grant-revoke-api-permissions)
- [App governance app policies](https://learn.microsoft.com/defender-cloud-apps/app-governance-app-policies-overview)
