# Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab

![Microsoft](https://img.shields.io/badge/Microsoft-Security-blue)
![Azure](https://img.shields.io/badge/Azure-Cloud-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-purple)
![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-EDR-green)
![Entra ID](https://img.shields.io/badge/Entra%20ID-Identity-blue)
![KQL](https://img.shields.io/badge/KQL-Detection%20Engineering-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

## Overview

This project is a practical **Microsoft Cloud SOC, EDR, detection engineering, threat hunting, incident investigation, and response laboratory** built around the Microsoft security ecosystem.

The lab demonstrates an end-to-end SOC workflow rather than isolated tool usage:

**Controlled Activity → Telemetry → Detection → Hunting → Correlation → Investigation → Response → Validation → Documentation**

The environment combines Microsoft Sentinel, Microsoft Defender for Endpoint, Microsoft Entra ID, Azure, Windows, KQL, PowerShell, Python, MITRE ATT&CK, and security automation.

The project is designed to demonstrate practical SOC capabilities relevant to **SOC Analyst, Security Operations, Detection Engineering, Threat Hunting, Microsoft Security, and Cloud Security** roles.

---

## Project Objectives

The primary objectives are to demonstrate practical ability to:

- Build and understand a Microsoft cloud SOC architecture
- Work with Microsoft Sentinel
- Deploy and investigate Microsoft Defender for Endpoint telemetry
- Analyze Microsoft Entra ID authentication activity
- Write practical KQL investigation and detection queries
- Build authentication and endpoint detections
- Correlate identity and endpoint activity
- Perform hypothesis-driven threat hunting
- Enrich and investigate indicators of compromise
- Conduct end-to-end incident investigations
- Perform controlled incident response and containment
- Build security automation using Sentinel/Logic Apps
- Use Python/API enrichment where appropriate
- Map detections and investigations to MITRE ATT&CK
- Validate detections using controlled scenarios
- Analyze false positives and tune detections
- Document security investigations using reproducible evidence

---

## Technology Stack

| Technology | Role in the Project |
|---|---|
| Microsoft Azure | Cloud platform and security infrastructure |
| Microsoft Sentinel | SIEM and cloud-native SOC platform |
| Microsoft Defender for Endpoint | EDR and endpoint telemetry |
| Microsoft Defender XDR | Security investigation and correlation |
| Microsoft Entra ID | Identity and authentication telemetry |
| KQL | Detection, investigation, correlation, and hunting |
| Windows | Endpoint telemetry source |
| PowerShell | Controlled endpoint activity and investigation |
| Python | Automation/API enrichment where applicable |
| MITRE ATT&CK | Adversary technique mapping |
| Logic Apps | Security automation / SOAR |
| VMware Workstation | Local virtualized lab environment |
| Git | Version control |
| GitHub | Portfolio and project repository |
| Visual Studio Code | Documentation and development environment |

---

## Lab Architecture

The project is designed around the following security workflow:

    ┌───────────────────────┐
    │   Controlled Activity │
    │   / Attack Scenario   │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Identity / Endpoint   │
    │ Entra ID / Windows    │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Security Telemetry    │
    │ Auth / Process /      │
    │ Network / Endpoint    │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Microsoft Defender    │
    │ for Endpoint / XDR    │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Microsoft Sentinel    │
    │ SIEM                  │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ KQL Detection / Hunt  │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Alert / Incident      │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ SOC Analyst           │
    │ Triage & Investigation│
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Response / Containment│
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │ Validation / Tuning   │
    │ / Documentation       │
    └───────────────────────┘

---

## Lab Environment

The laboratory combines Microsoft cloud services with local virtual machines.

### Microsoft Cloud

- Azure subscription
- Microsoft Entra ID tenant
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Microsoft 365 administrative environment

### Local Virtual Environment

- Windows 10 workstation
- Windows Server 2022 Active Directory Domain Controller
- Ubuntu Linux
- Kali Linux
- VMware Workstation

The Windows 10 workstation acts as the primary endpoint telemetry source for Defender for Endpoint investigations.

---

## Project Workflow

The project follows a progressive SOC engineering workflow.

### Phase 1 — Environment and Telemetry

- SOC architecture
- Azure environment
- Entra ID
- Defender for Endpoint
- Windows endpoint
- Sentinel integration
- Telemetry validation

### Phase 2 — Detection Engineering

- KQL fundamentals
- Authentication detections
- Password-spray and brute-force scenarios
- Failed-authentication → successful-authentication analysis
- PowerShell detection
- Process execution analysis
- LOLBin-related detection
- Identity and endpoint correlation

### Phase 3 — Threat Hunting

- Hypothesis-driven hunting
- Authentication hunting
- Endpoint hunting
- Identity-to-device investigation
- IOC enrichment
- Advanced hunting

### Phase 4 — Incident Investigation

- Alert triage
- Scope assessment
- Timeline construction
- Identity investigation
- Endpoint investigation
- Evidence collection
- Root-cause analysis
- Containment recommendations

### Phase 5 — Response and Automation

- Controlled endpoint isolation
- Test-account containment
- Session revocation
- Process termination
- Indicator blocking where appropriate
- Sentinel automation
- Logic Apps
- Python/API enrichment

### Phase 6 — Validation and Tuning

- Detection validation
- False-positive analysis
- Detection tuning
- MITRE ATT&CK coverage
- SOC metrics
- Final end-to-end simulation
- Independent investigation
- Recruiter-quality repository review

---

## Detection Engineering

The project focuses on practical detections that can be reproduced and validated.

Planned detection areas include:

### Authentication

- Excessive authentication failures
- Password-spray behavior
- Brute-force behavior
- Failed authentication followed by successful authentication
- Suspicious authentication patterns

### Endpoint

- Suspicious PowerShell activity
- Process execution
- Parent-child process relationships
- Suspicious command-line activity
- LOLBin-related behavior

### Correlation

- Identity activity followed by endpoint activity
- User → device → process correlation
- Authentication → execution timelines
- Cross-source investigation

Every important detection follows the validation chain:

**Scenario → Telemetry → Query/Rule → Alert/Result → Investigation → Conclusion**

---

## Threat Hunting

Threat hunting is performed using explicit hypotheses rather than only searching for existing alerts.

Example hunting hypotheses include:

- A password spray may be targeting multiple accounts.
- Suspicious PowerShell execution may indicate malicious activity.
- A compromised identity may access an unusual endpoint.
- Identity activity may be followed by suspicious endpoint execution.

Each hunt is documented using:

**Hypothesis → Data Source → Query → Observation → Conclusion → Next Action**

---

## Incident Investigation

The project includes end-to-end incident investigations designed to demonstrate how a SOC analyst progresses from an initial alert to a defensible conclusion.

Investigation activities include:

- Alert triage
- Initial evidence collection
- User identification
- Source IP analysis
- Device identification
- Process analysis
- Timeline construction
- Scope assessment
- Evidence correlation
- Containment recommendation
- Final investigation report

The investigation process emphasizes evidence-based conclusions rather than assumptions.

---

## MITRE ATT&CK Mapping

Relevant detections, hunts, and investigations are mapped to MITRE ATT&CK techniques where appropriate.

Example techniques include:

- **T1110 — Brute Force**
- **T1059.001 — PowerShell**

Additional techniques will be added only when supported by completed and validated project activities.

MITRE coverage is maintained under:

    mitre-coverage/

---

## KQL Query Library

Reusable KQL queries are organized by investigation purpose:

    kql/
    ├── authentication/
    ├── endpoint/
    ├── correlation/
    └── hunting/

Queries are documented with:

- Investigation purpose
- Data source/table
- Query logic
- Expected behavior
- Observed result
- Analyst interpretation
- Relevant detection or hunting use case

---

## Repository Structure

    Project-05-Microsoft-Cloud-SOC/
    │
    ├── architecture/
    │   └── architecture diagrams and data-flow documentation
    │
    ├── attacks/
    │   └── controlled attack and scenario documentation
    │
    ├── automation/
    │   └── Sentinel/Logic Apps/Python automation
    │
    ├── detections/
    │   └── detection engineering documentation
    │
    ├── docs/
    │   └── Day00.md, Day01.md, Day02.md, ...
    │
    ├── hunting/
    │   └── hypothesis-driven threat hunting reports
    │
    ├── investigations/
    │   └── incident investigation reports and timelines
    │
    ├── kql/
    │   ├── authentication/
    │   ├── correlation/
    │   ├── endpoint/
    │   └── hunting/
    │
    ├── mitre-coverage/
    │   └── MITRE ATT&CK technique coverage
    │
    ├── screenshots/
    │   ├── Day00/
    │   ├── Day01/
    │   ├── Day02/
    │   ├── Day03/
    │   └── ...
    │
    ├── validation/
    │   └── detection validation records
    │
    ├── .gitignore
    └── README.md

---

## Evidence and Documentation Strategy

Evidence is treated as part of the technical implementation rather than decoration.

Each project day contains relevant screenshots and documentation.

Screenshots are named consistently:

    DayXX-01-Description.png
    DayXX-02-Description.png
    DayXX-03-Description.png

Evidence should demonstrate meaningful states such as:

- Configuration
- Telemetry
- Detection results
- Query execution
- Alerts
- Incidents
- Investigation timelines
- Response actions
- Validation results

Unnecessary screenshots are avoided.

The repository is documented progressively rather than reconstructed after the project is finished.

---

## Current Progress

### Day 00 — Environment Preparation

**Status: Completed**

Completed activities include:

- Azure environment preparation
- Azure subscription and tenant alignment
- Microsoft Defender for Endpoint preparation
- Windows 10 endpoint onboarding
- Defender device inventory verification
- Microsoft Entra tenant verification
- Microsoft 365 administrative environment verification
- VS Code documentation workspace
- Git repository initialization
- GitHub repository creation
- Evidence directory creation
- Day 0 evidence collection
- Day 0 documentation

The primary Windows 10 endpoint is successfully onboarded into Microsoft Defender for Endpoint and available for subsequent telemetry and investigation activities.

### Day 01

**Status: Next**

Focus:

- SOC architecture
- Azure resources
- Log Analytics
- Microsoft Sentinel
- Telemetry flow
- Initial architecture evidence

---

## Project Roadmap

| Day | Focus | Status |
|---:|---|---|
| 00 | Environment preparation | Completed |
| 01 | SOC architecture & cloud environment | Planned |
| 02 | Entra ID & identity telemetry | Planned |
| 03 | Defender for Endpoint | Planned |
| 04 | Sentinel & telemetry integration | Planned |
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

## Target Project Metrics

The following are **project targets, not completed results**.

Final metrics will only be added after the corresponding work has been completed and verified.

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

---

## Recruiter and Interview Value

This project is designed to demonstrate an end-to-end Microsoft SOC workflow rather than simple familiarity with individual security products.

The intended technical narrative is:

> Built a Microsoft Cloud SOC environment using Microsoft Sentinel, Defender for Endpoint, and Microsoft Entra ID; generated controlled identity and endpoint activity; collected and analyzed security telemetry; developed KQL detections; performed hypothesis-driven threat hunting; correlated identity and endpoint activity; investigated incidents; documented response actions; and implemented security automation.

Each claim will be supported by repository evidence, including:

- Architecture
- KQL queries
- Detection logic
- Screenshots
- Validation records
- MITRE ATT&CK mappings
- Hunting reports
- Investigation reports
- Response documentation
- Automation workflows

The repository is structured so that an interviewer can follow the investigation from:

**Architecture → Telemetry → Detection → Validation → Investigation → Response**

---

## Security and Privacy

This repository is intended to be publicly viewable.

No secrets or sensitive credentials should be committed.

The repository must not contain:

- Passwords
- API keys
- Access tokens
- Client secrets
- HEC tokens
- Recovery codes
- MFA secrets
- Private certificates
- Sensitive authentication information

Screenshots are reviewed before publication and sensitive information is redacted where necessary.

---

## Validation Standard

The project prioritizes reproducibility and evidence over the number of tools or detections.

A detection should not be counted as completed simply because a query was written.

A completed detection should demonstrate:

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

Project metrics will be calculated only from completed and verified work.

---

## Project Status

**Current Phase:** Environment Preparation → SOC Architecture

**Day 0:** Completed

**Next Milestone:** Day 1 — SOC Architecture and Cloud Environment Configuration

---

## Author

**Ananthan D**

Cybersecurity | SOC | Blue Team | Detection Engineering

Focus areas:

- Security Operations
- SIEM
- EDR
- Microsoft Sentinel
- Microsoft Defender
- Microsoft Entra ID
- KQL
- Threat Hunting
- Detection Engineering
- Incident Investigation
- MITRE ATT&CK

---

## Disclaimer

This project is a controlled cybersecurity laboratory created for learning, detection engineering, threat hunting, investigation practice, and portfolio demonstration.

All attack simulations and security testing activities are performed only within the controlled laboratory environment.

The project does not represent testing against systems or organizations without authorization.