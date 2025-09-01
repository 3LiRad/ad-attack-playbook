# 08) Process Memory Leak → Recover Masked Password via Dump + Strings
**ATT&CK:** T1003 (OS Credential Dumping), T1055 (Process Injection – related telemetry)  
**Scope:** Authorized lab/assessment only.

## Objective
Document the risk where an app shows a masked password (••••••) but keeps cleartext creds in **process memory**. In a lab, create a **process dump** and search for secrets (e.g., with `strings` / `findstr` / text viewer).

## Lab Assumptions
- **Workstation:** `WS-ALPHA` — 10.8.10.70
- **App:** `monview.exe` (imaginary tool showing masked creds)
- **Target account:** `administrator@DRAGONBALL.local` (imaginary)

## Procedure (doc-only)
1. On `WS-ALPHA`, reproduce the app’s masked-login screen.
2. **Create dump file** for the process (Task Manager → Details → right-click `monview.exe` → *Create dump file*). This writes a `*.dmp` under `%TEMP%`.
3. Copy the dump to an analysis box and search for likely tokens:
   - Windows:
     ```powershell
     findstr /i /c:"password" /c:"user" C:\Temp\monview.dmp
     ```
   - Sysinternals:
     ```powershell
     strings.exe C:\Temp\monview.dmp | findstr /i password
     ```
   - Linux:
     ```bash
     strings monview.dmp | grep -iE 'pass(word)?|user(name)?|admin'
     ```
4. If cleartext/partially masked credentials appear, record **where** they were found and how to prevent it.

## Telemetry to Collect
- **Security:** 4688 (process creation) for `Taskmgr.exe`/`procdump.exe`
- **Sysmon:** 11/15 (FileCreate/Stream) for `*.dmp` in `%TEMP%`; **10** if tools touch LSASS (shouldn’t for this demo)
- **EDR:** dump-creation or memory-read alerts

## SIEM Starters (Splunk)
```spl
# creation of large *.dmp files in Temp
index=sysmon (EventCode=11 OR EventCode=15) TargetFilename="*\\AppData\\Local\\Temp\\*.dmp"
| stats count by Computer, TargetFilename, Image

# procdump/taskmgr usage
index=wineventlog EventCode=4688
| search NewProcessName="*\\taskmgr.exe" OR NewProcessName="*\\procdump.exe"
| stats values(ParentProcessName) by NewProcessName, AccountName, Computer
```
---
## Mitigations

- **No admin creds on user workstations:** use **PAWs/jump hosts**.
- **Application-side:** never keep **cleartext** secrets in memory; use secure strings; **zeroize** buffers; prefer **token-based auth**.
- **OS/EDR:** block **dump creation** by policy/EDR; restrict **SeDebugPrivilege**; disable **WDigest**; enforce **Credential Guard** (for LSASS).
- **DevSecOps:** threat-model apps that handle secrets; add **memory scans** in QA.
