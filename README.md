# Microsoft Cloud SOC Lab: Identity Detection, Endpoint Hunting & Case Triage

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-7252aa)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft-Entra_ID-0078D4)
![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender_for_Endpoint-0078D4)
![KQL](https://img.shields.io/badge/Query_Language-KQL-orange)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)

A hands-on SOC lab built on Microsoft's security stack. It develops and validates KQL detection logic for **repeated failed Entra ID sign-ins** and **endpoint discovery commands**, triages a set of lab-account sign-ins, and records the work in case-management automation and a validation matrix.

**Security objective:** show the analyst workflow of query development, controlled testing, evidence-based triage, and documentation, while keeping test results separate from real-world detection claims.

**Technologies:** Microsoft Entra ID (`SigninLogs`), Microsoft Defender for Endpoint (`DeviceProcessEvents`), a Microsoft Sentinel-enabled Log Analytics workspace, KQL, Defender portal case management and automation rules, MITRE ATT&CK.

---

## Table of Contents

- [Microsoft Cloud SOC Lab: Identity Detection, Endpoint Hunting \& Case Triage](#microsoft-cloud-soc-lab-identity-detection-endpoint-hunting--case-triage)
  - [Table of Contents](#table-of-contents)
  - [Project Overview](#project-overview)
  - [Key Achievements and Results](#key-achievements-and-results)
  - [Architecture](#architecture)
  - [Technology Stack](#technology-stack)
  - [Implementation Phases](#implementation-phases)
  - [Detection Engineering and Hunting](#detection-engineering-and-hunting)
    - [Detection: Repeated Authentication Failures (`P05-D06-DET-001`)](#detection-repeated-authentication-failures-p05-d06-det-001)
    - [Hunting query: Repeated Discovery Activity](#hunting-query-repeated-discovery-activity)
    - [Representative investigation query](#representative-investigation-query)
  - [Authentication Investigation](#authentication-investigation)
  - [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
  - [Case-Management Automation](#case-management-automation)
  - [Evidence and Validation](#evidence-and-validation)
  - [Repository Structure](#repository-structure)
  - [Exploring and Reproducing the Lab](#exploring-and-reproducing-the-lab)
  - [Skills Demonstrated](#skills-demonstrated)
  - [Conclusion](#conclusion)

---

## Project Overview

SOC analysts spend much of their time deciding whether a pattern of events, such as repeated failed logins or a burst of discovery commands, is routine or worth escalating. This project practices that decision process end to end in a controlled lab:

- **Identity telemetry:** Entra ID sign-in logs were queried to establish a baseline, then a repeated-failure detection was written and tested.
- **Endpoint telemetry:** a Windows 10 lab endpoint (`p05-win10-ep`) generated process events that a Defender Advanced Hunting query was built to find.
- **Triage:** 20 sign-in events for one lab account and source IP were analysed using result codes and a chronological timeline, then related to a Defender case.
- **Case handling:** automation rules tag cases and create an investigation task.
- **Validation:** results were consolidated into a validation matrix that separates real telemetry, synthetic data, controlled endpoint activity, and case evidence.

All activity took place in an authorised personal lab. The synthetic test and the controlled endpoint test show that the query logic works. They are not evidence of a real attack.

---

## Key Achievements and Results

| Area | Verified result | Evidence |
|---|---|---|
| Real-telemetry baseline | 38 Entra ID sign-in records over 7 days (35 successful, 3 failed); detection returned **0 matching groups** | [Day 06 validation](validation/day06-repeated-authentication-failures-validation.md) |
| Authentication detection (synthetic test) | 4 synthetic failures within 6 minutes returned **1 matching group** against a threshold of 3 in 15 minutes: PASS | [Day 14 matrix](validation/day14-detection-validation-matrix.md) |
| Endpoint discovery hunting query | 1 matching group containing **2 process events** from one controlled command (`cmd.exe /c "whoami && hostname"`): PASS | [Day 07 validation](validation/day07-repeated-discovery-validation.md) |
| Authentication triage | **20 sign-in events** analysed: 11 successful, 6 invalid-credential (`50126`), 3 other; counts reconcile to the total | [Day 15 investigation](investigations/day15-authentication-incident-investigation.md) |
| Case automation | **2 automation rules**, **4 successful execution records**, **3 distinct cases** (195, 196, 197) | [Day 13 validation](validation/day13-automation-validation.md) |
| Case review | Defender Case 513 reviewed: tag `P05-SOC-Lab` and investigation task confirmed present | [Day 15 validation](validation/day15-end-to-end-investigation-validation.md) |
| Validation matrix | **7 entries**: 5 PASS, 1 baseline evaluated, 1 workflow demonstrated | [Day 14 matrix](validation/day14-detection-validation-matrix.md) |
| ATT&CK mapping | 3 techniques mapped: T1110, T1082, T1033 | Detection and validation docs |

**How to read these numbers.** The matrix entries measure different things (events, matched groups, execution records, distinct cases), and the validation record itself says they should not be added together or turned into one success percentage. The 5 PASS results are tests the lab author designed with known inputs, so they confirm query logic and do not measure real-world detection performance. The one detection run against real telemetry returned no matches.

---

## Architecture

![Project 05 complete SOC architecture](architecture/Project05-SOC-Complete-Architecture.png)

**Data flow as documented in the repository:**

1. **Sources:** Entra ID sign-in activity, and process activity on the Windows 10 endpoint `p05-win10-ep` onboarded to Microsoft Defender for Endpoint.
2. **Storage and query:** sign-in data is queried from `SigninLogs` in the Sentinel-enabled Log Analytics workspace `law-project05-soc`; endpoint data is queried from `DeviceProcessEvents` through Defender Advanced Hunting.
3. **Detection and hunting:** KQL logic groups failed sign-ins by user, source IP, and 15-minute window, and groups discovery-related process events by device, account, and 15-minute window.
4. **Investigation:** result-code analysis and chronological timelines for sign-in events; Defender case and alert review.
5. **Case handling:** automation rules tag cases and add an investigation task.
6. **Validation:** consolidated in the detection validation matrix.

| Diagram | Purpose |
|---|---|
| [Day 01 architecture](architecture/Project05-SOC-Architecture-Day01.png) | Initial lab environment |
| [Day 15 architecture](architecture/Project05-SOC-Architecture-Day15.png) | Authentication investigation and case workflow |
| [Complete architecture](architecture/Project05-SOC-Complete-Architecture.png) | Project-wide view |

---

## Technology Stack

| Technology | Purpose | How it was used |
|---|---|---|
| Microsoft Entra ID | Identity telemetry | `SigninLogs` source for the detection baseline and the Day 15 triage |
| Microsoft Defender for Endpoint | Endpoint telemetry | `DeviceProcessEvents` queried through Advanced Hunting |
| Microsoft Sentinel | SIEM platform | Enabled on the lab workspace; used as the SIEM layer for KQL-based investigation |
| Log Analytics workspace (`law-project05-soc`) | Log storage and query | Workspace queried with KQL for sign-in data |
| KQL | Detection and investigation | Filtering, grouping, `summarize`/`countif`, time bucketing, synthetic `datatable()` tests |
| Microsoft Defender portal | Case management | Case and alert review, automation rules, investigation tasks |
| Windows 10 endpoint (`p05-win10-ep`) | Lab endpoint | Controlled command execution to generate process telemetry |
| MITRE ATT&CK | Technique mapping | Labelling detections and tests (T1110, T1082, T1033) |
| Git / GitHub | Documentation | Version-controlled queries, reports, and evidence |

---

## Implementation Phases

| Phase | Objective | What was done | Verification | Evidence |
|---|---|---|---|---|
| 1. Environment | Establish telemetry sources | Log Analytics workspace, identity telemetry, and a Windows endpoint onboarded to Defender | Process and sign-in data queryable | [`docs/`](docs/) |
| 2. Authentication detection | Detect repeated failed sign-ins | Wrote detection `P05-D06-DET-001`; ran it against a 7-day real baseline and a synthetic dataset | 0 matches on real data; 1 match on synthetic data | [Detection](detections/day06-repeated-authentication-failures.md), [validation](validation/day06-repeated-authentication-failures-validation.md) |
| 3. Endpoint hunting | Find discovery-command activity | Wrote a `DeviceProcessEvents` hunting query; ran a controlled command on the endpoint | Query returned the expected group | [Validation](validation/day07-repeated-discovery-validation.md) |
| 4. Case automation | Standardise case handling | Configured case-tagging and investigation-task rules | Run histories recorded for cases 195, 196, 197 | [Rules](automation/day13-automation-rules.md), [validation](validation/day13-automation-validation.md) |
| 5. Validation | Consolidate results | Built a 7-entry matrix with status definitions | Counts reconciled across reports | [Matrix](validation/day14-detection-validation-matrix.md) |
| 6. Triage | Practice an end-to-end investigation | Analysed 20 sign-in events, reviewed Case 513, checked tag and task | Evidence-based assessment recorded | [Investigation](investigations/day15-authentication-incident-investigation.md) |

---

## Detection Engineering and Hunting

### Detection: Repeated Authentication Failures (`P05-D06-DET-001`)

| Field | Value |
|---|---|
| Data source | Entra ID `SigninLogs` |
| Logic | Failed sign-ins grouped by user principal name + source IP + 15-minute window |
| Threshold | 3 or more failures per group |
| Lookback | 7 days |
| ATT&CK | T1110 Brute Force |
| Validation | Synthetic test PASS (4 events, 1 group). Real baseline: 0 groups. |

Query: [`kql/authentication/day06-repeated-authentication-failures.kql`](kql/authentication/day06-repeated-authentication-failures.kql)

The threshold and window are initial lab values that would need tuning against normal authentication behaviour before any production use. Meeting the threshold means a pattern warrants review. It does not confirm a brute-force attack. The documented analyst steps are: check result codes and descriptions, review timing and frequency, look for a successful sign-in after the failures, review related identity activity, and escalate only if the evidence supports it.

### Hunting query: Repeated Discovery Activity

| Field | Value |
|---|---|
| Data source | Defender `DeviceProcessEvents` |
| Logic | Process events containing `whoami`, `hostname`, `ipconfig`, `systeminfo`, `net user`, or `net localgroup`, grouped by device + account + 15-minute window |
| Threshold | 2 or more matching events per group |
| ATT&CK | T1082, T1033 |
| Validation | PASS: one group, two events, from `cmd.exe /c "whoami && hostname"` on `p05-win10-ep` as `soc-lab-user` |

Query: [`kql/endpoint/day07-repeated-discovery-activity.kql`](kql/endpoint/day07-repeated-discovery-activity.kql)

The commands tested are legitimate administrative commands, so this validates query behaviour and not malicious activity.

### Representative investigation query

Outcome summary used in the Day 15 triage (account and IP replaced with placeholders; the original query is in [`kql/authentication/day15-end-to-end-investigation.kql`](kql/authentication/day15-end-to-end-investigation.kql)):

```kusto
SigninLogs
| where TimeGenerated >= ago(24h)
| where UserPrincipalName =~ "<lab-account-upn>"
| where IPAddress == "<source-ip>"
| summarize
    TotalEvents = count(),
    SuccessfulSignIns = countif(ResultType == "0"),
    InvalidCredentialFailures = countif(ResultType == "50126"),
    OtherEvents = countif(ResultType != "0" and ResultType != "50126"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
```

**What it does:** counts outcomes for one account and source IP over 24 hours. `ResultType` `0` is success and `50126` is an invalid username or password. **Observed output:** 20 total, 11 successful, 6 invalid-credential, 3 other. **Analyst use:** the counts show whether failures and successes are mixed for the same account and IP, which leads to the timeline and result-code queries in the same file.

---

## Authentication Investigation

**Investigation ID:** `P05-D15-INV-001` | **Related detection:** `P05-D06-DET-001` | **Defender case:** 513

| Step | What was done |
|---|---|
| Scope | One lab account and one source IP, 24-hour lookback, applications Azure Portal and Office365 Shell WCSS-Client |
| Outcome analysis | 20 events: 11 successful, 6 `50126`, 3 other (including `50140`, the "Keep me signed in" interruption) |
| Timeline | Successful Azure Portal sign-in, then two `50126` failures about 78 seconds apart, then further successes |
| Case review | Case 513, `P05 - Repeated Invalid Credential Attempts`: severity Low, status Active, classification Unclassified, 1 associated alert, no entities displayed in the incident graph |
| Case handling | Tag `P05-SOC-Lab` and an investigation task present (task status "Not set") |
| Assessment | **Authentication activity investigated; malicious activity not confirmed** |

The investigation record states that the evidence does not establish an attacker, a brute-force attack, or account compromise. It also notes that six failures across 24 hours do not show that three or more occurred inside a single 15-minute window, so the investigation is not presented as a confirmed match for the Day 06 detection. The case remains open pending further validation.

An endpoint-side investigation record is also in the repository: [`investigations/day11-endpoint-incident-investigation.md`](investigations/day11-endpoint-incident-investigation.md).

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Use case | Validation status |
|---|---|---|---|
| Credential Access | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Repeated failed sign-ins detection | Logic validated on synthetic data only; 0 matches on real baseline |
| Discovery | [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082/) | `hostname` in discovery hunting query | Query validated on controlled endpoint activity |
| Discovery | [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) | `whoami` in discovery hunting query | Query validated on controlled endpoint activity |

Three techniques are mapped. The mappings describe behaviours the queries target and are not claims of broad ATT&CK coverage.

---

## Case-Management Automation

Two automation rules in the Defender portal handle lab cases: one applies the `P05-SOC-Lab` tag and one creates an investigation task. Rule definitions: [`automation/day13-automation-rules.md`](automation/day13-automation-rules.md).

| Rule | Case | Recorded result |
|---|---|---|
| `P05 - Auto-Tag SOC Lab Cases` | 196 | Success |
| `P05 - Tag Invalid Credential Incidents` | 195 | Success |
| `P05 - Tag Invalid Credential Incidents` | 196 | Success |
| `P05 - Tag Invalid Credential Incidents` | 197 | Success |

Status: **configured; 4 successful execution records documented.** These counts come from displayed run history and do not measure overall reliability. On Case 513 the task was created but its status was "Not set", so the evidence shows task creation and not task completion. This is case-handling automation. It does not perform containment or remediation.

Evidence: [Day 13 validation](validation/day13-automation-validation.md), [Day 15 automation validation](automation/day15-investigation-automation-validation.md).

---

## Evidence and Validation

| Evidence | What it shows |
|---|---|
| [Detection validation matrix](validation/day14-detection-validation-matrix.md) | 7 test and workflow entries with expected result, observed result, and status |
| [Day 06 validation](validation/day06-repeated-authentication-failures-validation.md) | Real baseline (0 matches) kept separate from the synthetic test (1 match) |
| [Day 07 validation](validation/day07-repeated-discovery-validation.md) | Controlled command, matching Defender process events, and the grouped query result |
| [Day 13 validation](validation/day13-automation-validation.md) | Automation run histories |
| [Day 15 validation](validation/day15-end-to-end-investigation-validation.md) | Triage results and Case 513 review |
| `screenshots/Day06/`, `Day07/`, `Day13/`, `Day15/` | Screenshots supporting each report |

**Status definitions used in the matrix:** *PASS*: the recorded test produced the expected result. *Baseline evaluated*: real telemetry was examined and no matching group was returned. *Demonstrated*: the workflow was performed and is supported by recorded evidence.

---

## Repository Structure

```text
Project-05-Microsoft-Cloud-SOC/
├── architecture/     # Day 01, Day 15, and complete architecture diagrams
├── automation/       # Automation rule documentation and validation
├── detections/       # Detection documents (Day 06, Day 15)
├── docs/             # Daily implementation notes
├── investigations/   # Day 11 endpoint and Day 15 authentication investigations
├── kql/
│   ├── authentication/   # Sign-in detection and investigation queries
│   └── endpoint/         # Endpoint hunting queries
├── mitre-coverage/   # ATT&CK mapping documentation
├── screenshots/      # Evidence screenshots by day
├── validation/       # Per-test reports and the Day 14 validation matrix
└── README.md
```

---

## Exploring and Reproducing the Lab

**To review the work without building anything:** open the [validation matrix](validation/day14-detection-validation-matrix.md), then follow its links to each detailed report and the matching screenshots.

**To reproduce it you would need:**

- A Microsoft Entra ID tenant and an Azure Log Analytics workspace receiving `SigninLogs`
- Microsoft Defender for Endpoint with a Windows 10 endpoint onboarded
- Access to the Defender portal for Advanced Hunting, case management, and automation rules

**Steps:** run the queries in `kql/` against your own telemetry, replacing the account and IP placeholders; run the synthetic `datatable()` test for the Day 06 detection; execute the controlled discovery command on your endpoint and run the Day 07 query; compare your results with the validation reports.

Case IDs, tenant details, and screenshots are specific to the original lab and will differ. No credentials or tokens are used in the repository files.

---

## Skills Demonstrated

| Category | Demonstrated by |
|---|---|
| Detection engineering | Defining a detection with ID, data source, threshold, and ATT&CK mapping; testing logic against synthetic data; separating real-baseline results from test results |
| Query-based investigation | KQL filtering, `summarize`/`countif`, time bucketing, result-code analysis, timeline construction |
| Identity security | Entra ID sign-in analysis, interpreting `ResultType` codes such as `0`, `50126`, `50140` |
| Endpoint security | Defender Advanced Hunting over `DeviceProcessEvents`, controlled endpoint testing |
| Case handling | Case and alert review, tagging, investigation tasks, automation rule run histories |
| Documentation | Validation matrix with status definitions, per-test reports, evidence-referenced findings, cautious assessments |

---

## Conclusion

This project shows the core loop of detection work: write a query, test it against known data, check it against real telemetry, triage what turns up, and record what the evidence does and does not support. It covers one authentication detection, one endpoint hunting query, one sign-in triage, and two case-handling automation rules, each documented with its validation status and kept separate from claims of real-world detection.