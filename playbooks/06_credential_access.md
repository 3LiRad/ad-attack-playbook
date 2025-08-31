# 06) Credential Access — LSASS / SAM / DPAPI / Browser
**ATT&CK:** T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores)  
**Scope:** Authorized lab/assessment only.

## Objective
Understand common credential sources targeted after a foothold and how to **detect** and **mitigate** them.

## Targets (Concept)
- **LSASS memory** — credential material / tickets in memory.
- **Registry hives** — `SAM`, `SECURITY`, `SYSTEM` for local account hashes.
- **DPAPI** — master keys and protected secrets (vaults, browsers).
- **Browsers** — saved passwords/cookies (Chromium/Edge/Firefox).

> **Legal/Ethical:** The items below are **documentation examples** for authorized labs only.

## Doc-Only Examples (authorized lab)
- **Hives (offline parse):**
```bash
# Copy hives from a lab host (requires admin on that host)
#   C:\Windows\System32\config\{SAM,SECURITY,SYSTEM}
# Then parse offline on analysis box:
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```
- **LSASS:** treat as **detect/block** scenario (use PPL/EDR); avoid in-lab memory dumps if not required.  
- **DPAPI:** document the master key → vault decryption flow (no live creds in repo).

## Telemetry to Collect
- **Sysmon:** Event **10** (process access to LSASS), **1/7** (proc create / image load).  
- **Security:** **4688** (suspicious tooling), **4624/4625** (logon anomalies).  
- **File/Registry:** access to `SAM`, `SECURITY`, `SYSTEM` paths; creation of dumps.  
- **Browser/DPAPI:** unusual reads of login data/Local State files (if audited).

## SIEM Analytics (Splunk examples)
```spl
# LSASS handle access (Sysmon 10)
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| stats values(Image) values(User) count by SourceImage, Computer, _time
| where count > 0
```

```spl
# Suspicious tool/process names
index=wineventlog EventCode=4688
| search NewProcessName="*\\procdump.exe" OR NewProcessName="*\\rundll32.exe" OR NewProcessName="*\\werfault.exe"
| stats values(ParentProcessName) by NewProcessName, AccountName, Computer
```

```spl
# Registry hive/file access (path auditing or Sysmon FileCreate/Stream)
index=sysmon (EventCode=11 OR EventCode=15)
| search TargetFilename="*\\System32\\config\\SAM" OR TargetFilename="*\\System32\\config\\SECURITY" OR TargetFilename="*\\System32\\config\\SYSTEM"
| stats values(Image) values(User) count by Computer, TargetFilename
```

## Mitigations
- **LSASS hardening:** run LSASS as **PPL**; enable **Windows Defender Credential Guard**.  
- **Least privilege:** minimize local admin; use **LAPS** for local admin rotation.  
- **Application control:** **WDAC/AppLocker**; block unsigned dumping tools.  
- **PowerShell security:** Module/ScriptBlock/Transcription logging; CLM where feasible.  
- **EDR tuning:** high-signal rules for LSASS access, hive reads, suspicious dump patterns.  
- **Admin tiering:** **PAWs** for privileged work; network isolation of admin workstations.

