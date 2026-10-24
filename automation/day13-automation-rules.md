# Day 13 — SOC Automation Rules

**Project:** Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab
**Platform:** Microsoft Sentinel and Microsoft Defender
**Environment:** `law-project05-soc`
**Focus:** Automated case tagging, investigation task creation, and security incident workflow management
**Status:** Implemented and execution-verified

---

## 1. Overview

This document describes the SOC automation rules implemented during Day 13 of the Microsoft Cloud SOC lab.

The objective was to streamline incident case management by automatically applying a consistent lab tag and creating structured investigation tasks for authentication-related security incidents.

The implementation uses Microsoft Defender's enhanced automation rules and the case-management functionality available in the lab environment.

### Automation objectives

* Standardize the identification of lab-generated security cases.
* Reduce repetitive manual case-management activities.
* Support consistent investigation workflows for repeated invalid credential attempts.
* Verify rule execution using the automation run history.
* Maintain evidence of the resulting case state.

---

## 2. Automation Architecture

```text
Microsoft Sentinel Analytics Rule
              |
              v
Repeated Invalid Credential Detection
              |
              v
Security Incident Created
              |
              v
Microsoft Defender Case Management
              |
              +-----------------------------+
              |                             |
              v                             v
   P05 - Auto-Tag SOC Lab Cases   P05 - Tag Invalid Credential Incidents
              |                             |
              v                             v
      Update Case / Tag              Update Case / Tag
              |                             |
              +--------------+--------------+
                             |
                             v
                    Automation Run History
                             |
                             v
                    Case Tag Verification
```

The architecture illustrates the intended case-management workflow. Each automation rule is configured and verified through its own execution history.

---

## 3. Rule 1 — P05 - Auto-Tag SOC Lab Cases

### 3.1 Purpose

This rule applies a consistent lab-identification tag to eligible cases when they are created.

The tag makes it easier to distinguish lab-related cases during investigation, filtering, and evidence collection.

### 3.2 Configuration

| Setting   | Value                          |
| --------- | ------------------------------ |
| Rule name | `P05 - Auto-Tag SOC Lab Cases` |
| Rule type | Enhanced rule                  |
| Trigger   | When case is created           |
| Condition | Case type equals Incident      |
| Action    | Update case                    |
| Tag       | `P05-SOC-Lab`                  |
| Status    | Active                         |

### 3.3 Execution workflow

1. A new eligible incident case is created.
2. The automation rule evaluates its trigger and configured conditions.
3. The rule executes the Update case action.
4. The configured lab tag is applied to the case.
5. The automation run history records the execution result.

### 3.4 Execution evidence

**Evidence file:** `screenshots/Day13/Day13-15-Automation-Execution-New-Cases.png`

![Auto-Tag SOC Lab Cases execution](../screenshots/Day13/Day13-15-Automation-Execution-New-Cases.png)

The captured execution history records a successful run for case ID 196.

**Evidence file:** `screenshots/Day13/Day13-08-Automation-Rules-Baseline.png`

![Automation rules baseline](../screenshots/Day13/Day13-08-Automation-Rules-Baseline.png)

The automation inventory documents the configured rules used in the lab.

---

## 4. Rule 2 — P05 - Tag Invalid Credential Incidents

### 4.1 Purpose

This rule targets incident cases associated with the repeated invalid credential detection and applies the lab-identification tag.

Its purpose is to make authentication-related lab cases easier to identify and organize during SOC investigation.

### 4.2 Configuration

| Setting            | Value                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| Rule name          | `P05 - Tag Invalid Credential Incidents`                                |
| Rule type          | Enhanced rule                                                           |
| Trigger            | When case is created                                                    |
| Condition 1        | Case type equals Incident                                               |
| Condition 2        | Analytic Rule Name matches `P05 - Repeated Invalid Credential Attempts` |
| Condition operator | AND between the configured conditions                                   |
| Action             | Update case                                                             |
| Tag                | `P05-SOC-Lab`                                                           |
| Status             | Active                                                                  |

### 4.3 Execution workflow

1. A case is created from the relevant authentication detection.
2. The rule checks whether the case is an incident.
3. The rule checks the associated analytic rule name.
4. When the conditions match, the Update case action executes.
5. The automation history records the execution result.

### 4.4 Execution evidence

**Evidence file:** `screenshots/Day13/Day13-19-Tag-Automation-Execution-Success.png`

![Tagging automation execution success](../screenshots/Day13/Day13-19-Tag-Automation-Execution-Success.png)

The captured execution history records successful runs for case IDs 195, 196, and 197.

**Evidence file:** `screenshots/Day13/Day13-14-Automated-Case-Tag-Verification.png`

![Automated case tag verification](../screenshots/Day13/Day13-14-Automated-Case-Tag-Verification.png)

The screenshot documents the case-tag verification stage.

**Evidence file:** `screenshots/Day13/Day13-16-Incident-Tag-Verification.png`

![Incident tag verification](../screenshots/Day13/Day13-16-Incident-Tag-Verification.png)

The incident view provides visual evidence of the lab tag.

---

## 5. Investigation Task Automation

### Task name

`Review Repeated Invalid Credential Attempts`

### Purpose

The task defines a consistent investigation workflow for authentication-related incidents.

### Task description

Review the affected account and source IP, investigate failed and successful sign-ins, identify suspicious post-authentication activity, and document the investigation findings.

### Recommended investigation procedure

1. Identify the affected user account.
2. Review the associated failed sign-in events.
3. Examine the source IP address and authentication error details.
4. Determine whether a successful sign-in occurred after the failures.
5. Review relevant sign-in risk indicators and geographical context.
6. Search for suspicious activity following authentication.
7. Record the investigation findings.
8. Recommend containment or escalation when justified by the evidence.

### Task configuration evidence

**Evidence file:** `screenshots/Day13/Day13-11-Automated-Task-Verification.png`

![Automated investigation task configuration](../screenshots/Day13/Day13-11-Automated-Task-Verification.png)

The screenshot documents the investigation task configured for the authentication detection.

---

## 6. Automation Monitoring and Verification

The automation run history provides execution-level evidence for the configured rules.

### Verified execution results

| Rule                                     | Case ID | Recorded result |
| ---------------------------------------- | ------: | --------------- |
| `P05 - Auto-Tag SOC Lab Cases`           |     196 | Success         |
| `P05 - Tag Invalid Credential Incidents` |     195 | Success         |
| `P05 - Tag Invalid Credential Incidents` |     196 | Success         |
| `P05 - Tag Invalid Credential Incidents` |     197 | Success         |

The table records the case IDs and successful execution results visible in the captured automation histories.

### Verification procedure

For each rule:

1. Open Microsoft Defender.
2. Navigate to the automation rules inventory.
3. Select the required rule.
4. Open its automation run history.
5. Review the triggering entity and case ID.
6. Confirm the execution status.
7. Open the corresponding case to inspect its tag.

### Related evidence

* `screenshots/Day13/Day13-12-Automation-Rules-Active.png`
* `screenshots/Day13/Day13-13-Automation-Rule-Execution-Success.png`
* `screenshots/Day13/Day13-15-Automation-Execution-New-Cases.png`
* `screenshots/Day13/Day13-18-Automation-Execution-Success.png`
* `screenshots/Day13/Day13-19-Tag-Automation-Execution-Success.png`

---

## 7. MITRE ATT&CK Context

The primary detection associated with these automation rules is:

| Field               | Value                                |
| ------------------- | ------------------------------------ |
| Detection           | Repeated Invalid Credential Attempts |
| MITRE ATT&CK tactic | Credential Access                    |
| Technique           | Brute Force                          |
| Technique ID        | T1110                                |

The automation rules support case organization and investigation workflow management. They do not independently determine whether the underlying activity is malicious.

The analyst must review authentication evidence before classifying the incident or recommending containment.

---

## 8. Operational Benefits

The implemented workflow demonstrates several practical SOC automation benefits:

* **Consistent case identification:** A common tag makes lab cases easier to locate.
* **Reduced repetitive work:** Case tagging can be applied automatically when rule conditions match.
* **Structured investigations:** A predefined task describes the expected authentication-investigation activities.
* **Auditable execution:** Automation run history provides evidence of individual rule executions.
* **Repeatable testing:** Case IDs and screenshots provide concrete references for reviewing test results.
* **Improved documentation:** Configuration and execution evidence can be maintained alongside the project.

---

## 9. Evidence Index

| Evidence                         | Path                                                                |
| -------------------------------- | ------------------------------------------------------------------- |
| Automation rules baseline        | `screenshots/Day13/Day13-08-Automation-Rules-Baseline.png`          |
| Automation rule created          | `screenshots/Day13/Day13-09-Automation-Rule-Created.png`            |
| Automation execution success     | `screenshots/Day13/Day13-10-Automation-Execution-Success.png`       |
| Investigation task configuration | `screenshots/Day13/Day13-11-Automated-Task-Verification.png`        |
| Active automation rules          | `screenshots/Day13/Day13-12-Automation-Rules-Active.png`            |
| Rule execution success           | `screenshots/Day13/Day13-13-Automation-Rule-Execution-Success.png`  |
| Case-tag verification            | `screenshots/Day13/Day13-14-Automated-Case-Tag-Verification.png`    |
| Auto-tag execution               | `screenshots/Day13/Day13-15-Automation-Execution-New-Cases.png`     |
| Incident-tag verification        | `screenshots/Day13/Day13-16-Incident-Tag-Verification.png`          |
| New-case tag and task evidence   | `screenshots/Day13/Day13-17-New-Case-Tag-And-Task-Verification.png` |
| Additional execution evidence    | `screenshots/Day13/Day13-18-Automation-Execution-Success.png`       |
| Tagging rule execution history   | `screenshots/Day13/Day13-19-Tag-Automation-Execution-Success.png`   |

---

## 10. Conclusion

Day 13 established two active enhanced automation rules for SOC case management in the Microsoft security environment.

The rules support automated lab tagging and authentication-related case organization. Execution history provides successful run records for both rules on case ID 196, with additional successful executions of the invalid-credential tagging rule on cases 195 and 197.

The implementation demonstrates how detection-generated incidents can be integrated with repeatable case-management workflows, supported by execution records and visual evidence.

**Result:** SOC automation configuration, case-tagging execution, and evidence collection documented for Project 05.
