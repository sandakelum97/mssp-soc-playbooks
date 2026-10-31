# PB-00 — Playbook template

> Copy this file when adding a new playbook. Keep every example generic — no client names, real UPNs, IPs, domains, ticket or incident numbers.

| Field | Value |
|---|---|
| Playbook ID | PB-XX |
| Version | 1.0 |
| Last reviewed | YYYY-MM-DD |
| Primary platforms | e.g. Microsoft Defender XDR, Microsoft Sentinel, Microsoft Entra ID |
| MITRE ATT&CK | Txxxx — Technique name |
| Reference | Link to the Microsoft Learn (or other vendor) source this playbook is based on |

---

## 1. Scope

What alert(s), incident type or customer report triggers this playbook, and what is out of scope.

## 2. Prerequisites

- Logging / licensing that must be in place (and what you lose if it isn't)
- Roles needed to investigate vs. to contain (least privilege)
- Customer approvals needed before containment (MSSP runbook / RACI)

## 3. Severity guide

| Condition | Suggested severity |
|---|---|
| ... | Low / Medium / High / Critical |

## 4. Triage (first 15 minutes)

1. Step — with the query to run (`kql/<folder>/<file>.kql`)
2. ...

Decision: **True positive / Benign true positive / False positive** — record the evidence for the decision.

## 5. Investigation

Ordered steps. Each step should say *what question it answers* and *which query or portal view answers it*.

## 6. Containment

Actions, who performs them, and whether customer approval is required.

## 7. Eradication & recovery

## 8. Closure & reporting

- Classification and determination set in Defender XDR / Sentinel
- Ticket note summary (see template below)
- Lessons learned / detection tuning follow-ups

### Ticket note template

**Summary:** One-line description of what happened.
**Scope:** Users / devices / mailboxes affected (counts, not names, when shared outside the ticket).
**Evidence:** Key findings with timestamps (UTC).
**Actions taken:** Containment and remediation steps, with times.
**Recommendations:** Hardening items for the customer.
**Status:** Open / Monitoring / Closed.

## 9. Queries used

| Query | Purpose |
|---|---|
| `kql/...` | ... |

## 10. References

- Microsoft Learn links
