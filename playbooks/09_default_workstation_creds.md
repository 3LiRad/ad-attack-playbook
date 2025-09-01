# 09) Default/Shared Workstation Creds → RDP/SMB Lateral
**ATT&CK:** T1021 (Remote Services), T1078 (Valid Accounts)  
**Scope:** Authorized lab/assessment only.

## Objective
Show how a default local credential (e.g., `tech:Welcome123!`) re-used across many workstations enables fast lateral movement.

## Lab Assumptions
- **Targets:** `WS-BETA` 10.8.10.75, `WS-GAMMA` 10.8.10.80 (imaginary)
- **Default local:** `tech / Welcome123!` (imaginary)

## Procedure (doc-only)
```bash
# sweep local admin reuse
crackmapexec smb 10.8.10.70-90 -u tech -p 'Welcome123!' --local-auth

# if RDP open on a host, validate interactively (lab only)
xfreerdp /u:tech /p:'Welcome123!' /v:10.8.10.80

```
## Telemetry to Collect

- **Auth:** **4624/4625**; **4672** (special privileges) on success
- **Network:** many **SMB/RDP** attempts from a single source

## SIEM Starters (Splunk)

```spl
# same local username authenticating to many workstations
index=wineventlog (EventCode=4624 OR EventCode=4625)
| search TargetUserName="tech"
| stats count by Computer
| where count>20
```
## Mitigations

- **LAPS/PLAP:** randomize local admin passwords per machine.
- **Restrict RDP:** allow only to jump hosts; add **MFA** where possible.
- **Remove shared locals:** disable/rename the built-in **Administrator**; break reuse patterns.
- **DLP/process:** scan file shares and deployment docs for default creds; **ban plaintext secrets**.

