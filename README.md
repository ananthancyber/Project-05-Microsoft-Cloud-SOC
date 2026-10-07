# Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab

![Microsoft](https://img.shields.io/badge/Microsoft-Security-blue)
![Azure](https://img.shields.io/badge/Azure-Cloud-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-purple)
![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-EDR-green)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft-Entra%20ID-blue)
![KQL](https://img.shields.io/badge/KQL-Detection%20Engineering-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

## Overview

This project is a hands-on **Microsoft Cloud SOC, EDR, identity telemetry, detection engineering, threat hunting, incident investigation, and response laboratory** built around the Microsoft security ecosystem.

The project is designed to demonstrate an evidence-driven SOC workflow:

**Controlled Activity → Telemetry → Detection → Hunting → Correlation → Investigation → Response → Validation → Documentation**

The lab combines:

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics
- Microsoft Defender for Endpoint
- Microsoft Defender
- Microsoft Entra ID
- KQL
- Windows
- PowerShell
- Python
- MITRE ATT&CK
- Security automation

The project is being developed to demonstrate practical capabilities relevant to:

**SOC Analyst · Security Operations · Detection Engineering · Threat Hunting · Microsoft Security · Cloud Security**

---

## Objectives

The project is designed to demonstrate practical ability to:

- Build a Microsoft cloud SOC architecture
- Configure Microsoft Sentinel and Log Analytics
- Work with Microsoft Defender for Endpoint
- Analyze Microsoft Entra ID identity and authentication telemetry
- Investigate authentication activity
- Develop KQL investigation and detection queries
- Build authentication and endpoint detections
- Correlate identity and endpoint activity
- Perform hypothesis-driven threat hunting
- Enrich and investigate indicators of compromise
- Conduct end-to-end incident investigations
- Perform controlled response and containment
- Build security automation
- Map validated activity to MITRE ATT&CK
- Validate detections using controlled scenarios
- Analyze false positives and tune detection logic
- Produce recruiter-ready technical documentation and evidence

---

# Lab Architecture

```text
                         ┌────────────────────────────┐
                         │   Controlled Activity      │
                         │   / Attack Scenario        │
                         └─────────────┬──────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    ▼                                     ▼
         ┌─────────────────────┐             ┌─────────────────────┐
         │ Microsoft Entra ID  │             │ Windows 10 Endpoint │
         │ Identity Telemetry  │             │ win10-client        │
         └──────────┬──────────┘             └──────────┬──────────┘
                    │                                   │
                    │ Sign-in / Auth                    │ Endpoint Telemetry
                    │                                   │
                    └──────────────┬────────────────────┘
                                   ▼
                     ┌────────────────────────────┐
                     │ Microsoft Defender for     │
                     │ Endpoint / Microsoft       │
                     │ Defender                  │
                     └────────────┬───────────────┘
                                  │
                                  ▼
                     ┌────────────────────────────┐
                     │ Microsoft Sentinel         │
                     │ SIEM                       │
                     └────────────┬───────────────┘
                                  │
                                  ▼
                     ┌────────────────────────────┐
                     │ Log Analytics Workspace     │
                     │ law-project05-soc           │
                     │                            │
                     │ KQL Investigation           │
                     │ Detection Engineering       │
                     │ Threat Hunting              │
                     └────────────┬───────────────┘
                                  │
                                  ▼
                     ┌────────────────────────────┐
                     │ SOC Analyst                 │
                     │                            │
                     │ Triage                     │
                     │ Investigation               │
                     │ Correlation                 │
                     │ Threat Hunting              │
                     │ Response                    │
                     └────────────────────────────┘
```

---

# Current Environment

## Microsoft Cloud

| Component | Configuration / Status |
|---|---|
| Azure Tenant | Personal Cybersecurity Lab |
| Azure Subscription | Azure subscription 1 |
| Azure Region | Central India |
| Resource Group | `rg-project05-soc` |
| Log Analytics Workspace | `law-project05-soc` |
| Microsoft Sentinel | Enabled |
| Sentinel Trial | Active |
| Microsoft Defender for Endpoint | Active |
| Microsoft Entra ID | Active |
| Windows Endpoint | `win10-client.corp.local` |

## Endpoint

| Attribute | Value |
|---|---|
| Hostname | `win10-client.corp.local` |
| OS | Windows 10 Pro 22H2 |
| Architecture | 64-bit |
| Domain | `corp.local` |
| Private IP | `192.168.159.133` |
| Device Type | Workstation |
| MDE Onboarding | Onboarded |

---

# Technology Stack

| Technology | Role |
|---|---|
| Microsoft Azure | Cloud platform and SOC infrastructure |
| Microsoft Sentinel | SIEM |
| Log Analytics | Central telemetry repository and KQL platform |
| Microsoft Defender for Endpoint | EDR and endpoint telemetry |
| Microsoft Defender | Unified SecOps experience |
| Microsoft Entra ID | Identity and authentication telemetry |
| KQL | Investigation, detection, correlation, hunting |
| Windows | Endpoint telemetry source |
| PowerShell | Controlled endpoint activity |
| Python | Automation / API enrichment |
| MITRE ATT&CK | Adversary technique mapping |
| Logic Apps | SOAR / automation |
| VMware Workstation | Local virtualized lab |
| Git | Version control |
| GitHub | Project repository |
| Visual Studio Code | Documentation and development |

---

# Completed Work

## Day 00 — Environment Preparation

**Status: ✅ Completed**

Completed:

- Azure environment prepared
- Azure subscription verified
- Microsoft Defender for Endpoint trial/environment prepared
- Tenant alignment completed
- Windows 10 endpoint onboarded
- Defender device inventory verified
- Microsoft Entra environment verified
- Microsoft 365 administrative environment verified
- Project repository created
- Documentation structure created
- Evidence structure created
- Day 00 documentation completed

---

## Day 01 — SOC Architecture & Cloud Environment

**Status: ✅ Completed**

### Infrastructure

- Created resource group `rg-project05-soc`
- Standardized the lab around **Central India**
- Created Log Analytics workspace `law-project05-soc`
- Activated Microsoft Sentinel
- Activated the Sentinel free-trial environment
- Verified the unified Microsoft Defender/Sentinel SecOps portal
- Reviewed Sentinel data connector baseline
- Verified Defender for Endpoint endpoint visibility

### Endpoint

- Verified `win10-client.corp.local`
- Confirmed device is visible in Microsoft Defender
- Confirmed endpoint onboarding status as **Onboarded**
- Established initial endpoint security baseline

### Documentation

- Environment inventory
- SOC architecture
- Telemetry/data-flow model
- Day 01 validation
- Day 01 evidence
- Day 01 documentation

Evidence:

```text
screenshots/Day01/
```

Documentation:

```text
docs/Day01.md
```

Architecture:

```text
architecture/Project05-SOC-Architecture-Day01.png
```

---

# Day 02 — Entra ID & Identity Telemetry

**Status: ✅ Completed**

Day 02 established the identity telemetry and authentication investigation baseline required for future authentication detection engineering.

## Identity Baseline

Reviewed the Microsoft Entra tenant and existing users.

The environment contained:

- `Ananthan Azure Admin` — Guest
- `ananthan D` — Member

The existing member identity was used to review authentication telemetry.

---

## Interactive Sign-in Telemetry

Reviewed Microsoft Entra interactive sign-in logs and confirmed availability of:

- Timestamp
- Request ID
- User
- Application
- Status
- Sign-in error code
- Source IP address

---

## Sign-in Event Investigation

Investigated an individual sign-in event and reviewed:

- User
- Username
- User ID
- Session context
- Application
- Application ID
- Resource
- Resource tenant
- Home tenant
- Client application

---

## Location and Network Context

Reviewed:

- Source IP
- Geographic location
- Autonomous System Number
- Global Secure Access status
- Named location context

---

## Authentication and MFA

Reviewed authentication details showing:

- Security Defaults
- Authentication state
- First-factor requirement
- MFA requirement
- MFA satisfaction
- Successful authentication context

---

## Conditional Access

Reviewed Conditional Access results showing:

- Security Defaults
- MFA grant control
- Successful policy evaluation

---

## Audit Logs

Reviewed the Entra Audit Logs page using the available User Management filter.

No matching rows were returned during the reviewed period.

This result was documented as a baseline observation rather than interpreted as a telemetry failure.

---

## Day 02 Evidence

```text
screenshots/Day02/
├── Day02-01-Entra-Sign-In-Logs-Baseline.png
├── Day02-02-Entra-Sign-In-Event-Details.png
├── Day02-03-Entra-Sign-In-Location-Details.png
├── Day02-04-Entra-Authentication-Details.png
├── Day02-05-Entra-Conditional-Access-Result.png
└── Day02-06-Entra-Audit-Logs-Baseline.png
```

Documentation:

```text
docs/Day02.md
```

---

# SOC Investigation Workflow Established

The identity investigation process established during Day 02 is:

```text
User
  ↓
Sign-in Event
  ↓
Source IP
  ↓
Location
  ↓
Device Context
  ↓
Application / Resource
  ↓
Authentication Details
  ↓
MFA
  ↓
Conditional Access
  ↓
Authentication Outcome
```

This workflow will later be extended into:

```text
Identity Activity
      ↓
Endpoint Activity
      ↓
Correlation
      ↓
Detection
      ↓
Investigation
      ↓
Response
```

---

# Detection Engineering

The project follows a telemetry-first approach.

A detection is not treated as complete simply because a query or rule has been written.

The validation model is:

```text
Controlled Scenario
        ↓
Expected Telemetry
        ↓
KQL / Detection Logic
        ↓
Detection Result / Alert
        ↓
Analyst Investigation
        ↓
Conclusion
        ↓
Validation Evidence
```

## Planned Authentication Detections

- Excessive authentication failures
- Password-spray behavior
- Brute-force behavior
- Failed authentication followed by successful authentication
- Suspicious authentication patterns

## Planned Endpoint Detections

- Suspicious PowerShell
- Process execution
- Parent-child process relationships
- Suspicious command-line activity
- LOLBin-related behavior

## Planned Correlation

- User → device correlation
- Authentication → endpoint activity
- Identity → process relationships
- Cross-source attack timelines

---

# Threat Hunting

Threat hunting will use explicit hypotheses rather than relying only on existing alerts.

Planned hunting areas include:

- Password spraying across accounts
- Suspicious PowerShell activity
- Unusual identity-to-endpoint access
- Identity activity followed by suspicious endpoint execution
- IOC-driven investigation

Each hunt will follow:

```text
Hypothesis
   ↓
Data Source
   ↓
Query
   ↓
Observation
   ↓
Conclusion
   ↓
Next Action
```

---

# Incident Investigation

The project will demonstrate a complete SOC investigation workflow covering:

- Alert triage
- Initial evidence collection
- Identity analysis
- Source IP analysis
- Device identification
- Process analysis
- Timeline construction
- Scope assessment
- Evidence correlation
- Containment recommendation
- Final reporting

The emphasis is on **evidence-based conclusions** rather than assumptions.

---

# MITRE ATT&CK

MITRE ATT&CK will be used to map validated adversary behaviors to relevant techniques.

Current project mapping examples include:

- **T1110 — Brute Force**
- **T1059.001 — PowerShell**

Additional techniques will only be added after the underlying activity has been completed and validated.

MITRE coverage:

```text
mitre-coverage/
```

---

# KQL Query Library

Reusable KQL will be organized by investigation purpose:

```text
kql/
├── authentication/
├── endpoint/
├── correlation/
└── hunting/
```

Each query will be documented with:

- Investigation purpose
- Data source/table
- Query logic
- Expected behavior
- Observed result
- Analyst interpretation
- Detection or hunting use case

---

# Repository Structure

```text
Project-05-Microsoft-Cloud-SOC/
│
├── architecture/
│   └── SOC architecture and data-flow diagrams
│
├── attacks/
│   └── Controlled attack/scenario documentation
│
├── automation/
│   └── Sentinel / Logic Apps / Python automation
│
├── detections/
│   └── Detection specifications and logic
│
├── docs/
│   ├── Day00.md
│   ├── Day01.md
│   ├── Day02.md
│   └── ...
│
├── hunting/
│   └── Threat-hunting reports
│
├── investigations/
│   └── Incident investigation reports
│
├── kql/
│   ├── authentication/
│   ├── endpoint/
│   ├── correlation/
│   └── hunting/
│
├── mitre-coverage/
│   └── MITRE ATT&CK coverage
│
├── screenshots/
│   ├── Day00/
│   ├── Day01/
│   ├── Day02/
│   └── ...
│
├── validation/
│   └── Detection validation records
│
├── .gitignore
└── README.md
```

---

# Evidence Strategy

Screenshots are treated as **technical evidence**, not decoration.

Evidence is captured only when it demonstrates a meaningful:

- Configuration
- Telemetry source
- Query result
- Detection result
- Alert
- Incident
- Investigation step
- Response action
- Validation result

Evidence naming follows:

```text
DayXX-01-Description.png
DayXX-02-Description.png
DayXX-03-Description.png
```

Daily documentation is created progressively to preserve the actual implementation sequence.

---

# Cost-Control Approach

This project is designed as a controlled personal laboratory.

The environment uses:

- Azure free-account resources where applicable
- Microsoft Sentinel trial resources
- A single primary Windows endpoint
- Minimal required cloud infrastructure
- Controlled telemetry sources
- No unnecessary continuously running Azure infrastructure

Unnecessary Sentinel connectors and optional analytics features are not enabled simply to increase the tool count.

The objective is to maximize practical SOC experience while keeping cloud consumption controlled.

---

# Project Roadmap

| Day | Focus | Status |
|---:|---|---|
| 00 | Environment preparation | ✅ Completed |
| 01 | SOC architecture & cloud environment | ✅ Completed |
| 02 | Entra ID & identity telemetry | ✅ Completed |
| 03 | Defender for Endpoint telemetry | 🔜 Next |
| 04 | Sentinel + telemetry integration | Planned |
| 05 | KQL fundamentals | Planned |
| 06 | Authentication detection engineering | Planned |
| 07 | Endpoint detection engineering | Planned |
| 08 | Identity + endpoint correlation | Planned |
| 09 | Hypothesis-driven threat hunting | Planned |
| 10 | Threat intelligence & advanced hunting | Planned |
| 11 | Full incident investigation | Planned |
| 12 | Incident response & containment | Planned |
| 13 | SOAR / Logic Apps + Python automation | Planned |
| 14 | Detection validation & SOC metrics | Planned |
| 15 | Final SOC simulation | Planned |
| 16 | Detection tuning & false-positive analysis | Planned |
| 17 | Independent SOC investigation | Planned |
| 18 | Final recruiter-quality review | Planned |

---

# Target Project Metrics

These are **targets only**, not completed results.

| Metric | Target |
|---|---:|
| Custom detections | 6–10 |
| KQL investigation queries | 10–15 |
| Threat-hunting hypotheses | 3–5 |
| Controlled attack scenarios | 3–4 |
| Full incident investigations | 2–3 |
| MITRE ATT&CK techniques | 5–8 |
| Telemetry sources | 3–5 |
| Automation workflows | 1–2 |
| Incident reports | 2–3 |
| Detection validation | Every detection |

Final metrics will be added only after the corresponding work has been completed and verified.

---

# Recruiter / Interview Value

This project is designed to demonstrate that I can work through a practical Microsoft SOC workflow rather than only list security tools.

The intended interview narrative is:

> **Built a Microsoft Cloud SOC environment using Microsoft Sentinel, Microsoft Defender for Endpoint, and Microsoft Entra ID. Established identity and endpoint telemetry, investigated authentication activity, developed KQL-based detections, performed threat hunting and cross-source correlation, investigated incidents, executed controlled response actions, and documented the complete evidence chain.**

The repository is structured so an interviewer can move from:

**Architecture → Telemetry → Detection → Validation → Investigation → Response**

and review the supporting evidence at each stage.

---

# Security & Privacy

This repository is public and must never contain secrets.

Never commit:

- Passwords
- API keys
- Access tokens
- Client secrets
- HEC tokens
- Recovery codes
- MFA secrets
- Private certificates
- Sensitive authentication information

Screenshots must be reviewed and sanitized before publication.

---

# Validation Standard

The project prioritizes **reproducibility, evidence, and technical depth** over the number of tools or claims.

A completed detection must demonstrate:

```text
Scenario
   ↓
Telemetry
   ↓
KQL / Detection Logic
   ↓
Result / Alert
   ↓
Investigation
   ↓
Conclusion
   ↓
Validation Evidence
```

Project metrics will only be published after the work has been completed and verified.

---

# Author

**Ananthan D**

Cybersecurity | SOC | Blue Team | Detection Engineering

### Focus Areas

`SOC Operations` · `SIEM` · `EDR` · `Microsoft Sentinel` · `Microsoft Defender` · `Microsoft Entra ID` · `KQL` · `Threat Hunting` · `Detection Engineering` · `Incident Investigation` · `MITRE ATT&CK`

---

# Disclaimer

This project is a controlled cybersecurity laboratory created for learning, detection engineering, threat hunting, incident investigation, response practice, and professional portfolio demonstration.

All attack simulations and security testing activities are performed only within the controlled laboratory environment and are intended for authorized security experimentation.