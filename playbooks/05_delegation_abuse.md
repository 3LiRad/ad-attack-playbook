# 05) Delegation Abuse — Unconstrained / Constrained / RBCD
**ATT&CK:** T1134 (Access Token Manipulation), Kerberos Delegation Abuse  
**Scope:** Authorized lab/assessment only.

## Objective
Explain how Kerberos **delegation misconfigurations** enable impersonation:
- **Unconstrained**: computers/services can receive **forwardable TGTs** for users → theft/reuse.
- **Constrained (KCD)**: a service can act on behalf of users **only** to specific SPNs.
- **Resource-Based Constrained Delegation (RBCD)**: target computer controls who may delegate **to it** via `msDS-AllowedToActOnBehalfOfOtherIdentity`.

## Environment (assumed)
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — **10.8.10.225**
- **Targets:** server(s) with delegation enabled or misconfigured.

## Preconditions / Misconfig Indicators
- **Unconstrained:** computer accounts with `TRUSTED_FOR_DELEGATION` (UAC flag); DCs excluded by policy but other servers sometimes not.
- **Constrained:** service accounts with broad `msDS-AllowedToDelegateTo` lists.
- **RBCD:** attacker (or relayed context) can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object.

> **Legal/Ethical:** Items below are doc examples for **authorized labs** only.

## Procedure (High-Level)
1. **Discover** delegation:
   - Unconstrained hosts; Constrained `msDS-AllowedToDelegateTo`; RBCD on computer objects.
2. **Unconstrained path (lab concept):**
   - Get code execution on the unconstrained host → extract cached **forwardable TGTs** → reuse to access other services.
3. **Constrained path (lab concept):**
   - From a service account with KCD, request S4U2Self/S4U2Proxy tickets to impersonate a user **to allowed SPNs**.
4. **RBCD path (lab concept):**
   - Gain write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on the **target** computer → add attacker-controlled computer/service → request S4U tickets to the target service as victim.

## Telemetry to Collect
- **Directory:** **5136** changes on:
  - `msDS-AllowedToDelegateTo`
  - `msDS-AllowedToActOnBehalfOfOtherIdentity`
  - `userAccountControl` (delegation flags)
- **Kerberos:** **4769/4770** surges for specific **ServiceName/SPN**; unusual impersonation chains.
- **Auth/Process:** **4624** Type 3/10 from unexpected hosts; **4688** spawning ticket tools.
- **EDR/Sysmon:** handles to LSASS (Sysmon **10**) on unconstrained hosts.

## SIEM Analytics (Splunk examples)
```spl
# RBCD writes
index=wineventlog EventCode=5136
| search AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| stats values(SubjectUserName) values(ObjectDN) count by _time, Computer

# Constrained delegation list changes
index=wineventlog EventCode=5136
| search AttributeLDAPDisplayName="msDS-AllowedToDelegateTo"
| stats values(SubjectUserName) values(ObjectDN) count by _time

# Ticket volume anomalies to a service (potential KCD abuse)
index=wineventlog EventCode=4769
| stats count by ServiceName, IpAddress
| where count > 200
```
## Mitigations

- **Unconstrained:** eliminate; move to **constrained** where required; protect **Tier-0** assets.
- **Constrained:** strictly scope `msDS-AllowedToDelegateTo`; avoid using **high-value SPNs** as targets.
- **RBCD:** lock down who can modify **computer objects**; treat computer accounts as **Tier-0** if they front Tier-0 services.
- **Protected Users / account flags:** prevent delegation for privileged identities; enable **“Account is sensitive and cannot be delegated.”**
- **Monitoring & Change Control:** alert on **5136** for delegation-related attributes; review periodically.
- **Admin Tiering:** enforce **T0/T1/T2** separation; use **PAWs** (Privileged Access Workstations).
