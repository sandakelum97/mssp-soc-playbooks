# Platform changes that affect these queries

Checked against Microsoft Learn on 2026-10-31. Re-check before relying on any date — Microsoft has moved some of them before.

| Change | Impact | Source |
|---|---|---|
| **Microsoft Sentinel leaves the Azure portal after 31 March 2027** and will only be available in the Microsoft Defender portal. (The earlier date of July 2026 was extended.) | Run Sentinel queries from Defender → *Advanced hunting* once the workspace is onboarded; `TimeGenerated` tables (SigninLogs, AuditLogs, etc.) and Defender `Timestamp` tables can then be queried side by side. | [Sentinel overview — retirement timeline](https://learn.microsoft.com/azure/sentinel/overview#microsoft-sentinel-in-the-azure-portal-retirement-timeline) |
| **`EntraIdSignInEvents` replaces `AADSignInEventsBeta`** (and `EntraIdSpnSignInEvents` replaces `AADSpnSignInEventsBeta`) in Defender advanced hunting. `AadDeviceId` is now `EntraIdDeviceId`. | Use the new table names in Defender XDR queries. Note numeric codes in that table: e.g. `ConditionalAccessStatus` 0/1/2 and `RiskState` 0–5 are integers, unlike the string values in Sentinel `SigninLogs`. | [EntraIdSignInEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-entraidsigninevents-table) · [Schema changes](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-changes) |
| **`Get-MessageTrace` → `Get-MessageTraceV2`**. V2 covers 90 days but at most 10 days per query; with no parameters it returns the last 48 hours. | Update message trace runbooks / scripts. | [Get-MessageTrace](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetrace) · [Message trace FAQ](https://learn.microsoft.com/exchange/monitoring/trace-an-email-message/message-trace-faq) |
| **`Search-Mailbox` is on-premises only.** | Use Purview Content search / `New-ComplianceSearch`, or Threat Explorer for email remediation. | [Search-Mailbox](https://learn.microsoft.com/powershell/module/exchangepowershell/search-mailbox) |
| **Audit (Standard) retention is 180 days** for records created on or after 17 October 2023. | Long investigations may need Audit Premium or SIEM retention. | [Audit log activities](https://learn.microsoft.com/purview/audit-log-activities) |
| **App governance** (in Defender for Cloud Apps) is where OAuth app policies are now created. | PB-03 recommendations. | [App governance app policies](https://learn.microsoft.com/defender-cloud-apps/app-governance-app-policies-overview) |

## Schema gotchas fixed in this repo

| Gotcha | Correct approach |
|---|---|
| `RiskEventTypes_V2` (SigninLogs) is a **string**; an empty list is `"[]"`, so `isnotempty()` is always true. | `RiskEventTypes_V2 !in ("", "[]")` |
| `EmailEvents.DeliveryAction` values are `Delivered`, `Junked`, `Blocked`, `Replaced` — there is no `DeliveredAsSpam`. | Use `Junked` for spam-foldered mail. |
| `DeviceNetworkEvents` has no `AccountName` column. | Use `InitiatingProcessAccountName`. |
| `take_any(*) by X` is not valid on its own. | `summarize take_any(*) by X` |
| In `SigninLogs`, `ResultType` is a **string**. | Compare with `"0"`, `"50126"` (quoted). |
| Graph activity ↔ sign-in correlation. | `MicrosoftGraphActivityLogs.SignInActivityId` == sign-in `UniqueTokenIdentifier`; first-party app-only tokens have no service principal sign-in row. |
