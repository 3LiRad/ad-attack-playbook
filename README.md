# Active Directory Attack Playbook — Red ↔ Blue (10.x.x.0/24)

> **Scope & Ethics** — Authorized defensive security and approved lab assessments only.

## Executive Summary
This repository documents high-probability Active Directory (AD) attack paths and pairs them with concrete detections and mitigations. It’s written in an enterprise style so reviewers can quickly map tactics to controls.

## Reference Architecture
**Domain:** `DRAGONBALL.local`  | **Subnet:** `10.x.x.0/24`

| Role | Hostname | IP |
|---|---|---|
| Domain Controller | DC01.DRAGONBALL.local | **10.x.x.225** |
| Certificate Authority | CA01.DRAGONBALL.local | **10.x.x.200** |
| Service Server | SVC01.DRAGONBALL.local | **10.x.x.15** |
| File Server | FILE01.DRAGONBALL.local | **10.x.x.25** |
| Workstation | WIN10-1.DRAGONBALL.local | **10.x.x.35** |
| Assessment Host | KALI | **10.x.x.50** |

flowchart LR
  %% Use a clean subgraph ID and put the label in brackets
  subgraph DRAGONBALL["DRAGONBALL.local (10.x.x.0/24)"]
    DC01["DC01 10.x.x.225"]
    CA01["CA01 10.x.x.200"]
    SVC01["SVC01 10.x.x.15"]
    FILE01["FILE01 10.x.x.25"]
    WIN10_1["WIN10-1 10.x.x.35"]
  end

  KALI["Kali 10.x.x.50"] --> WIN10_1
  WIN10_1 --> SVC01
  SVC01 --> DC01
  DC01 --> CA01

