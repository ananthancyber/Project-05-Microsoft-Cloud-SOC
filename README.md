# Microsoft Cloud SOC, EDR & Threat Hunting Lab

### Project 05 
![Project Status](https://img.shields.io/badge/Status-In%20Progress-yellow)
![Microsoft Azure](https://img.shields.io/badge/Microsoft%20Azure-Cloud-blue)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-purple)
![Microsoft Defender](https://img.shields.io/badge/Microsoft%20Defender-Endpoint%20Security-blue)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Identity%20Security-blue)
![KQL](https://img.shields.io/badge/KQL-Investigation%20%26%20Hunting-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Framework-red)

A hands-on Microsoft security operations laboratory focused on cloud security monitoring, identity investigation, endpoint telemetry, KQL-based investigations, detection engineering, threat hunting, and incident response.

**Primary focus:** Entry-Level SOC Analyst | Security Operations | Blue Team | Microsoft Security

---

## Table of Contents

- [Project Overview](#project-overview)
- [Project Objectives](#project-objectives)
- [Lab Architecture](#lab-architecture)
- [Technology Stack](#technology-stack)
- [Environment Configuration](#environment-configuration)
- [Implementation Progress](#implementation-progress)
- [Identity Investigation](#identity-investigation)
- [Endpoint Investigation](#endpoint-investigation)
- [KQL Investigation Workflow](#kql-investigation-workflow)
- [Detection Engineering Methodology](#detection-engineering-methodology)
- [Threat Hunting Methodology](#threat-hunting-methodology)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Repository Structure](#repository-structure)
- [Evidence and Validation](#evidence-and-validation)
- [Project Roadmap](#project-roadmap)
- [Skills Demonstrated](#skills-demonstrated)
- [Author](#author)

---

## Project Overview

This project involves building and documenting a Microsoft Cloud Security Operations Center (SOC) laboratory using Microsoft Azure, Microsoft Sentinel, Microsoft Defender for Endpoint, Microsoft Entra ID, and Kusto Query Language (KQL).

The goal is to develop practical SOC investigation skills by examining security telemetry, analyzing authentication and endpoint activity, developing investigation queries, and progressively building detection and incident-response capabilities.

Rather than treating the project as a tool-installation exercise, the lab follows an evidence-driven approach:

**Security Activity → Telemetry Collection → Investigation → Detection → Correlation → Response → Validation → Documentation**

The project is being developed in stages, with daily documentation, query files, screenshots, and validation records maintained in this repository.

### Project Scope

- Microsoft cloud security monitoring
- Identity and authentication investigation
- Endpoint telemetry analysis
- KQL investigation queries
- Authentication and endpoint detection engineering
- Identity and endpoint correlation
- Hypothesis-driven threat hunting
- MITRE ATT&CK mapping
- Incident investigation and response
- Security automation and detection validation

**Project status:** In progress. Completed activities are documented separately from planned capabilities.

---

## Project Objectives

The objectives of this project are to:

1. Establish a Microsoft security monitoring environment.
2. Configure and examine Microsoft Sentinel and Log Analytics.
3. Investigate identity and authentication events in Microsoft Entra ID.
4. Analyze endpoint process activity using Microsoft Defender for Endpoint.
5. Develop reusable KQL queries for SOC investigations.
6. Investigate suspicious authentication and process-execution patterns.
7. Correlate identity and endpoint evidence where the available telemetry supports it.
8. Develop and validate detection logic using controlled laboratory activity.
9. Practice threat hunting and incident investigation.
10. Document findings with supporting technical evidence.

---

## Lab Architecture

The laboratory uses Microsoft cloud security services and a Windows endpoint to explore the collection and investigation of security telemetry.

```text
                  ┌──────────────────────────┐
                  │  Microsoft Entra ID      │
                  │  Identity & Sign-ins     │
                  └────────────┬─────────────┘
                               │
                               ▼
                  ┌──────────────────────────┐
                  │ Authentication Telemetry │
                  │ Sign-ins & Audit Events  │
                  └────────────┬─────────────┘
                               │
                               │
                               ▼
┌─────────────────────┐   ┌──────────────────────────┐
│ Windows 10 Endpoint │──▶│ Microsoft Defender for   │
│                     │   │ Endpoint                 │
│ Process Activity    │   │ Endpoint Security Data   │
└─────────────────────┘   └────────────┬─────────────┘
                                       │
                                       ▼
                            ┌────────────────────────┐
                            │ Microsoft Sentinel     │
                            │ SIEM                   │
                            └────────────┬───────────┘
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │ Log Analytics          │
                            │ KQL Investigation      │
                            └────────────┬───────────┘
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │ SOC Investigation      │
                            │                        │
                            │ Query & Analyze        │
                            │ Correlate Evidence     │
                            │ Hunt for Threats       │
                            │ Validate Findings     │
                            └────────────────────────┘
```

**Architecture note:** The diagram represents the intended investigation workflow. The availability of a particular data source in a workspace or portal must be verified independently; the diagram does not imply that every integration or alert pipeline has been validated.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Microsoft Azure | Cloud laboratory infrastructure |
| Microsoft Sentinel | SIEM and security investigation platform |
| Azure Log Analytics | Security data storage and KQL queries |
| Microsoft Defender for Endpoint | Endpoint security telemetry and investigation |
| Microsoft Entra ID | Identity and authentication investigation |
| Kusto Query Language (KQL) | Log analysis, filtering, aggregation, and correlation |
| Windows 10 | Endpoint telemetry source |
| PowerShell | Controlled endpoint activity and validation |
| MITRE ATT&CK | Adversary technique classification |
| Python | Planned security automation and enrichment |
| Azure Logic Apps | Planned security orchestration and automation |
| VMware Workstation | Local virtualization environment |
| Git and GitHub | Version control and project documentation |
| Visual Studio Code | Query development and documentation |

---

## Environment Configuration

The following resources form the core of the laboratory.

### Azure Environment

| Component | Configuration |
|---|---|
| Azure Resource Group | `rg-project05-soc` |
| Log Analytics Workspace | `law-project05-soc` |
| Azure Region | Central India |
| Microsoft Sentinel | Enabled |
| Microsoft Entra ID | Identity investigation source |
| Microsoft Defender for Endpoint | Endpoint security platform |

### Windows Endpoint

| Attribute | Configuration |
|---|---|
| Operating System | Windows 10 |
| Device Role | Laboratory workstation |
| Domain | `corp.local` |
| Defender Onboarding | Onboarded |
| Primary Use | Endpoint telemetry and investigation |

The endpoint is used to examine process activity and investigate available security events.

Sensitive tenant information, credentials, tokens, and unnecessary internal network details are intentionally excluded from this public README.

---

## Implementation Progress

The project follows an 18-day implementation plan.

### Day 00 — Environment Preparation

**Status: Completed**

- Prepared the Azure and Microsoft security laboratory.
- Reviewed tenant and subscription access.
- Prepared the Windows endpoint.
- Verified endpoint visibility in Microsoft Defender.
- Created the project repository and documentation structure.
- Established an evidence collection workflow.

Documentation: `docs/Day00.md`

### Day 01 — SOC Architecture and Cloud Environment

**Status: Completed**

- Created the resource group `rg-project05-soc`.
- Created the Log Analytics workspace `law-project05-soc`.
- Enabled Microsoft Sentinel.
- Reviewed the security monitoring environment.
- Verified endpoint visibility and onboarding status.
- Documented the laboratory architecture and initial configuration.

Documentation: `docs/Day01.md`

Evidence: `screenshots/Day01/`

### Day 02 — Microsoft Entra ID and Identity Telemetry

**Status: Completed**

Investigated the available identity and authentication information in Microsoft Entra ID.

Activities included:

- Reviewing interactive sign-in logs.
- Examining user and application information.
- Inspecting sign-in timestamps and authentication outcomes.
- Reviewing source IP and geographic context.
- Examining authentication details and MFA information.
- Reviewing Conditional Access results.
- Inspecting the available audit-log baseline.

The investigation established an identity-telemetry baseline for later authentication analysis.

Documentation: `docs/Day02.md`

Evidence: `screenshots/Day02/`

### Day 03 — Defender for Endpoint Telemetry

**Status: Completed**

See `docs/Day03.md` for the recorded implementation and evidence.

### Day 04 — Telemetry Integration Validation

**Status: Completed**

Validated the availability of identity and endpoint telemetry in the configured investigation environment.

The recorded work covered:

- Endpoint process and device telemetry.
- Entra ID sign-in and audit-log availability.
- Review of the existing telemetry integration.
- Documentation of validation observations and limitations.

**Important:** Defender alert and incident integration was not treated as verified without supporting evidence.

Documentation: `docs/Day04-telemetry-integration-validation.md`

Evidence: `screenshots/Day04/`

### Day 05 — KQL Investigation Fundamentals

**Status: Completed**

Developed and executed KQL queries to examine endpoint process activity and authentication events.

Investigation activities included:

- Filtering process events.
- Reviewing PowerShell activity.
- Aggregating process events.
- Examining process activity by account.
- Reviewing command-line information.
- Investigating authentication outcomes.
- Grouping authentication activity by IP address.
- Examining repeated failed sign-ins.
- Reviewing process activity over time.

The queries and evidence are maintained in the repository.

Documentation: `docs/Day05.md`

Query directories:

- `kql/authentication/`
- `kql/endpoint/`
- `kql/correlation/`
- `kql/hunting/`

Evidence: `screenshots/Day05/`

**Interpretation note:** Query counts are observations from specific time windows, not permanent baseline values or proof of malicious activity.

### Day 06 — Authentication Investigation and Validation

**Status: Completed**

Documented the investigation and validation of repeated authentication failures.

Validation record: `validation/day06-repeated-authentication-failures-validation.md`

### Day 07 — Endpoint Investigation and Discovery Activity

**Status: Completed**

Performed controlled endpoint activities and examined the resulting endpoint telemetry.

Activities included:

- Creating and verifying a test directory and file locally.
- Reviewing process events for the laboratory endpoint.
- Investigating PowerShell process activity.
- Examining process names and parent-process relationships.
- Reviewing available endpoint event data.
- Recording validation observations and limitations.

A local test file was confirmed to exist on the endpoint. Its corresponding custom file event was not observed in the queried telemetry during the test, so the file-creation action is not presented as a confirmed file-event detection.

Documentation: `docs/Day07.md`

Query: `kql/endpoint/day07-repeated-discovery-activity.kql`

Validation: `validation/day07-repeated-discovery-validation.md`

Evidence: `screenshots/Day07/`

### Day 08–18 — Remaining Implementation

The remaining stages will progressively cover identity and endpoint correlation, threat hunting, threat intelligence, incident investigation, response, automation, validation, and final portfolio packaging.

The roadmap below identifies the planned work.

---

## Identity Investigation

Identity investigation is a foundational part of the laboratory.

The Day 02 investigation established familiarity with the available sign-in fields and authentication context.

### Investigation Workflow

```text
Sign-in Event
     │
     ▼
Identify the User
     │
     ▼
Review Timestamp and Outcome
     │
     ▼
Inspect Source IP
     │
     ▼
Review Application and Resource
     │
     ▼
Examine Authentication and MFA
     │
     ▼
Review Conditional Access
     │
     ▼
Determine Whether Further Investigation Is Required
```

### Questions an Analyst Should Ask

- Which user account generated the event?
- Was the sign-in successful or unsuccessful?
- What application or resource was accessed?
- What source IP address was recorded?
- Is the location consistent with expected activity?
- Was MFA required, and what does the authentication record show?
- Did Conditional Access allow or block the sign-in?
- Is there other evidence supporting a suspicious-activity hypothesis?

A failed sign-in is not automatically malicious. The conclusion must consider the event context and supporting evidence.

---

## Endpoint Investigation

Endpoint investigations use the available Microsoft Defender for Endpoint telemetry.

### Areas of Investigation

- Process execution
- Executable names and paths
- Process command lines
- Parent-process relationships
- Account context
- Event timestamps
- Repeated or unusual process activity

### Investigation Workflow

```text
Endpoint Event
     │
     ▼
Identify Device and Timestamp
     │
     ▼
Inspect Process Name and Path
     │
     ▼
Review Command Line
     │
     ▼
Inspect Parent Process
     │
     ▼
Examine Account Context
     │
     ▼
Search for Related Activity
     │
     ▼
Document Findings and Limitations
```

Process names alone do not establish malicious behavior. The analyst must consider the process path, command line, parent process, account context, timing, and other available evidence.

---

## KQL Investigation Workflow

KQL is used to filter, aggregate, and investigate available security telemetry.

The repository organizes queries by investigation purpose.

| Query Category | Purpose |
|---|---|
| Authentication | Investigate sign-in activity and authentication outcomes |
| Endpoint | Analyze process execution and endpoint activity |
| Correlation | Explore relationships across identity and endpoint evidence |
| Hunting | Investigate defined hypotheses using available telemetry |

### Example: Investigating Endpoint Process Activity

```kusto
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where DeviceName =~ "p05-win10-ep"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

This query examines recent process events for the laboratory endpoint and displays useful investigation fields.

**Expected use:** Review the available process activity and identify events that may require deeper investigation.

**Important:** Table availability, field names, query permissions, and time-window results depend on the data source and environment in which the query is executed. This example is intended for the Microsoft Defender advanced-hunting environment where `DeviceProcessEvents` is available.

---

## Detection Engineering Methodology

The project follows a validation-first approach to detection engineering.

Writing a query is only one part of developing a useful detection.

```text
Define a Security Hypothesis
           │
           ▼
Identify the Required Telemetry
           │
           ▼
Develop the Query
           │
           ▼
Execute Against Available Data
           │
           ▼
Inspect the Results
           │
           ▼
Validate the Detection Logic
           │
           ▼
Document Limitations
           │
           ▼
Tune and Retest
```

### Planned Authentication Detection Use Cases

- Repeated authentication failures.
- Excessive failures involving one account.
- Failed sign-ins followed by successful authentication.
- Potential password-spray patterns.
- Unusual authentication activity requiring further review.

### Planned Endpoint Detection Use Cases

- Suspicious PowerShell command lines.
- Unusual process execution.
- Suspicious parent-child process relationships.
- Repeated discovery-related activity.
- Process activity that warrants further investigation.

A query result is not automatically an alert, and an alert is not automatically a confirmed incident. Detection rules, alert generation, and incident creation must each be validated separately.

---

## Identity and Endpoint Correlation

A later project stage will investigate whether identity and endpoint events can be meaningfully correlated.

Potential investigation pivots include:

- User identity.
- Device identity.
- Event timestamp.
- Source IP address.
- Authentication outcome.
- Endpoint process activity.

Correlation must use reliable identifiers and appropriate time windows.

For example, a sign-in and a process event occurring close together in time do not, by themselves, prove that the sign-in caused the process execution. Identity mappings and supporting evidence must be examined before drawing conclusions.

---

## Threat Hunting Methodology

Threat hunting will be hypothesis-driven.

Each hunt should document:

1. **Hypothesis** — What suspicious behavior is being investigated?
2. **Data source** — Which telemetry is needed?
3. **Query** — How will relevant events be identified?
4. **Observations** — What did the query actually return?
5. **Analysis** — What does the evidence support?
6. **Conclusion** — Is the hypothesis supported, unsupported, or inconclusive?
7. **Next steps** — What additional investigation is required?

Planned hunting topics include suspicious authentication patterns, PowerShell activity, endpoint process relationships, and identity-to-endpoint activity.

---

## MITRE ATT&CK Mapping

The MITRE ATT&CK framework will be used to classify validated behaviors and organize detection coverage.

Potential areas of investigation include:

| Technique | Name | Project Context |
|---|---|---|
| T1110 | Brute Force | Authentication investigation and repeated failures |
| T1059.001 | PowerShell | Endpoint command-line investigation |

These techniques are investigation areas, not claims that a successful attack or validated detection has already occurred.

Additional mappings will be documented when supported by the activity performed and the available evidence.

Coverage documentation: `mitre-coverage/`

---

## Repository Structure

```text
Project-05-Microsoft-Cloud-SOC/
│
├── architecture/
│   └── Architecture diagrams
│
├── automation/
│   └── Planned automation artifacts
│
├── docs/
│   ├── Day00.md
│   ├── Day01.md
│   ├── Day02.md
│   ├── Day03.md
│   ├── Day04-telemetry-integration-validation.md
│   ├── Day05.md
│   ├── Day06.md
│   ├── Day07.md
│   └── Day08.md
│
├── hunting/
│   └── Threat-hunting documentation
│
├── investigations/
│   └── Investigation reports
│
├── kql/
│   ├── authentication/
│   ├── endpoint/
│   ├── correlation/
│   └── hunting/
│
├── mitre-coverage/
│   └── ATT&CK mappings
│
├── screenshots/
│   ├── Day00/
│   ├── Day01/
│   ├── Day02/
│   ├── Day03/
│   ├── Day04/
│   ├── Day05/
│   ├── Day06/
│   ├── Day07/
│   └── Day08/
│
├── validation/
│   ├── day06-repeated-authentication-failures-validation.md
│   └── day07-repeated-discovery-validation.md
│
├── .gitignore
└── README.md
```

*The repository will evolve as additional project stages are completed. Directory contents and filenames should be checked against the current repository.*

---

## Evidence and Validation

Technical evidence is collected to support configuration, investigation, and validation claims.

Evidence may include:

- Resource configuration.
- Endpoint onboarding status.
- Sign-in log observations.
- KQL query results.
- Process investigation details.
- Detection and alert results.
- Investigation timelines.
- Validation records.

### Validation Principles

- Record the query and time window.
- Distinguish expected results from observed results.
- Document empty results rather than assuming a detection succeeded.
- Do not label benign activity as malicious without supporting evidence.
- Do not claim alert or incident creation unless it was verified.
- Document telemetry gaps and investigation limitations.
- Keep screenshots consistent with the written findings.

Daily documentation is maintained under `docs/`, while supporting screenshots and validation records are stored separately.

---

## Project Roadmap

The project follows the planned 18-day sequence.

| Day | Focus | Status |
|---:|---|---|
| 00 | Environment preparation | Completed |
| 01 | SOC architecture and cloud environment | Completed |
| 02 | Entra ID and identity telemetry | Completed |
| 03 | Defender for Endpoint telemetry | Completed |
| 04 | Telemetry integration validation | Completed |
| 05 | KQL investigation fundamentals | Completed |
| 06 | Authentication investigation and validation | Completed |
| 07 | Endpoint investigation and discovery activity | Completed |
| 08 | Identity and endpoint correlation | In Progress |
| 09 | Threat hunting | Planned |
| 10 | Threat intelligence and IOC investigation | Planned |
| 11 | Incident investigation | Planned |
| 12 | Incident response and containment | Planned |
| 13 | Security automation and SOAR | Planned |
| 14 | Detection validation and SOC metrics | Planned |
| 15 | End-to-end SOC simulation | Planned |
| 16 | Detection tuning and false-positive analysis | Planned |
| 17 | Independent SOC investigation | Planned |
| 18 | Final documentation and portfolio review | Planned |

---

## Skills Demonstrated

The project is designed to develop and demonstrate practical skills in:

### Security Operations

- Security telemetry review.
- Authentication investigation.
- Endpoint event analysis.
- Evidence collection.
- Investigation documentation.
- Analytical reasoning.

### SIEM and KQL

- Query filtering and projection.
- Aggregation and grouping.
- Time-based investigation.
- Process and authentication analysis.
- Query result interpretation.

### Endpoint Security

- Process execution investigation.
- Command-line analysis.
- Parent-process review.
- Endpoint telemetry validation.
- Investigation of unusual activity.

### Identity Security

- Sign-in investigation.
- Authentication outcome analysis.
- Source IP and location review.
- MFA and Conditional Access review.
- Identity investigation fundamentals.

### Detection and Threat Hunting

- Hypothesis development.
- Detection logic development.
- Query-based hunting.
- MITRE ATT&CK awareness.
- Validation and false-positive considerations.

---

## Author

**Ananthan D**

Aspiring SOC Analyst | Cybersecurity | Blue Team

**Areas of focus:**  
Microsoft Sentinel · Microsoft Defender for Endpoint · Microsoft Entra ID · KQL · SIEM · EDR · Threat Hunting · Detection Engineering · Incident Investigation

GitHub: [@ananthancyber](https://github.com/ananthancyber)


---

## Disclaimer

This project is a personal cybersecurity laboratory intended for learning, defensive security investigation, detection engineering, and professional portfolio development.

All testing is intended for authorized, controlled environments. Findings and detection claims are limited to the activities performed and the evidence recorded in this repository.