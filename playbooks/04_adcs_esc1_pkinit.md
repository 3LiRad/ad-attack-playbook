# 04) ADCS ESC1 → Admin TGT via PKINIT
**ATT&CK:** Certificate Abuse / Kerberos (PKINIT)  
**Scope:** Authorized lab/assessment only.

## Objective
Identify a certificate template vulnerable to **ESC1** (e.g., `ENROLLEE_SUPPLIES_SUBJECT` + Client Authentication EKU with broad enroll permissions). Demonstrate how a certificate could be misused to authenticate via **PKINIT** and obtain a TGT.

## Environment (assumed)
- **Domain:** `DRAGONBALL.local`
- **DC:** `DC01` — **10.8.10.225**
- **Enterprise CA (ADCS):** `CA01` — **10.8.10.200**
- **Operator box:** `KALI` — **10.8.10.50`

## Preconditions / Misconfig Indicators
- A template grants **Enroll** to non-admins (e.g., `Domain Users`).  
- Template has **Client Authentication** EKU and allows **subject supply** (`ENROLLEE_SUPPLIES_SUBJECT`).  
- ADCS web enrollment (`/certsrv`) reachable and not using **EPA**.

> **Legal/Ethical:** The items below are **documentation examples** for authorized labs only.

## Discovery (Doc-Only)
- On a domain host, inventory templates:
  - `certutil -template` *(high level enumeration)*  
  - Confirm **ENROLLEE_SUPPLIES_SUBJECT**, EKUs, and **Security** tab (who can **Enroll**).

## Conceptual Abuse Flow (Doc-Only)
1. Request a certificate on the vulnerable template, supplying a **SAN** that names a high-value principal (e.g., `administrator`).  
2. Use the issued **PFX** to perform **PKINIT** and obtain a Kerberos **TGT** for that identity.  
3. Pass the ticket (PTT) to reach admin context in the lab.

> Keep your repo defensive: document that this is possible, then focus on **detections & mitigations**.

## Telemetry to Collect
- **ADCS:** Enrollment logs (requester, template, SAN).  
- **Authentication:** Post-enrollment spikes in **4768/4769** for the targeted identity.  
- **Web:** IIS logs for `/certsrv` if web enrollment is used.

## SIEM Analytics (Splunk examples)
```spl
# ADCS enrollment anomalies (if forwarded)
index=adcs sourcetype=enrollment_logs
| stats count by Template, Requester, SAN
| where count > 0

# Surge of Kerberos for a privileged account after enrollments
index=wineventlog (EventCode=4768 OR EventCode=4769)
| search TargetUserName="administrator"
| timechart count span=5m

```

## Mitigations

- **Template hygiene:** remove `ENROLLEE_SUPPLIES_SUBJECT` from general-use templates; restrict **Enroll** to least privilege.
- **EKUs:** keep **minimal EKUs** (only what’s required).
- **Approvals & workflow:** require manager/PKI admin approval for sensitive templates.
- **Monitoring:** forward and alert on **ADCS** enrollments (template, requester, **SAN** deviations).
- **Web hardening:** enforce **EPA** on ADCS web endpoints; prefer **LDAPS/Kerberos**-backed enrollment where possible.
- **Inventory:** regularly review templates, permissions, and CA configuration with change control.

