# 07) Password Reuse — External → Internal Blast Radius
**ATT&CK:** TA0006 (Credential Access), T1110 (Credential Stuffing)  
**Scope:** Authorized lab/assessment only.

## Objective
Show how a password captured externally (SaaS/VPN/web) can work **inside AD**, enabling lateral movement and follow-on abuse (e.g., Kerberoasting).

## Lab Assumptions
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — 10.8.10.225
- **Example user:** `alex.j` (imaginary) with leaked pass **Winter2024!** (imaginary)
- **Hosts to test:** 10.8.10.30, 10.8.10.40, 10.8.10.60 (imaginary)

## Procedure (high-level)
1. Validate whether external creds also work in AD (doc-only).
2. If valid, test low-risk network auth (SMB/WinRM) to **verify blast radius**.
3. Optional: demonstrate a chained risk (Kerberoast) to show impact, not to own prod.

## Doc-Only Examples
```bash
# Validate against AD (TGT/TGS behavior visibility in logs)
crackmapexec smb 10.8.10.30-60 -d DRAGONBALL.local -u alex.j -p 'Winter2024!'

# If valid, show how it enables Kerberoast request volume (no cracking shown here)
GetUserSPNs.py DRAGONBALL.local/alex.j:'Winter2024!' -dc-ip 10.8.10.225 -request | tee tgs.out
```
## Telemetry to Collect

- **Auth:** 4624/4625 (Type 3/10), lockouts 4740
- **Kerberos:** 4768/4769 spikes after reuse is validated
- **Network:** failed/success SMB/WinRM bursts from unusual source
---
## SIEM Starters (Splunk)
```sql
# same username seen across multiple internal hosts in a short window
index=wineventlog (EventCode=4624 OR EventCode=4625)
| stats count by TargetUserName, Computer
| where count>50

# kerberoast surge following reuse
index=wineventlog EventCode=4769
| timechart span=5m count by ServiceName limit=10
```
---

## Mitigations

- **Separation of realms:** use different secrets for external apps vs. **AD**; enforce **SSO + MFA**.
- **Password filters:** block known-breached passwords; set minimum length **14–16+**.
- **Detection:** alert on rapid **4624/4625** for the same user across many hosts; correlate with **external login telemetry**.
- **Account hygiene:** rotate any account confirmed reused; educate users about reuse risk.
