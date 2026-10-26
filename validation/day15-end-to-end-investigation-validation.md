# Day 15 — End-to-End Investigation Validation

## 1. Validation Overview

| Field              | Details                                                    |
| ------------------ | ---------------------------------------------------------- |
| Project            | Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab |
| Day                | 15                                                         |
| Validation ID      | P05-D15-VAL-001                                            |
| Validation Type    | End-to-end investigation workflow                          |
| Data Source        | Microsoft Entra ID `SigninLogs`                            |
| Case Platform      | Microsoft Defender                                         |
| Related Case       | 513                                                        |
| Overall Assessment | Workflow demonstrated; malicious activity not confirmed    |

## 2. Validation Objectives

The validation aimed to establish whether the lab demonstrated the following SOC activities:

1. Query authentication telemetry using KQL.
2. Identify failed and successful sign-in events.
3. Examine authentication result codes and timestamps.
4. Review the associated Defender case and alert.
5. Verify case-tagging automation.
6. Verify investigation-task creation.
7. Record findings without overstating the evidence.

## 3. Authentication Telemetry Validation

The KQL investigation used a 24-hour lookback and filtered events by the selected lab account and source IP.

| Metric                                                | Observed Result |
| ----------------------------------------------------- | --------------: |
| Total sign-in events                                  |              20 |
| Successful sign-ins (`ResultType == "0"`)             |              11 |
| Invalid-credential failures (`ResultType == "50126"`) |               6 |
| Other events                                          |               3 |

The result-code analysis identified `0`, `50126`, and `50140`.

The timeline showed successful sign-ins before and after two visible invalid-credential failures.

**Validation result:** Authentication telemetry was queried, summarized, and reviewed.

## 4. Detection-Threshold Consideration

The existing detection `P05-D06-DET-001` uses a threshold of at least three failed sign-in records for the same user and source IP within a 15-minute window.

The Day 15 summary recorded six invalid-credential failures across the selected 24-hour scope.

That aggregate count does not prove that the three-failure threshold was met within any individual 15-minute window.

**Validation result:** The authentication activity was investigated, but a match against the existing detection threshold has not been established by the aggregate result alone.

## 5. Defender Case Validation

| Field             | Observed Result                              |
| ----------------- | -------------------------------------------- |
| Case ID           | 513                                          |
| Case name         | `P05 - Repeated Invalid Credential Attempts` |
| Severity          | Low                                          |
| Status            | Active                                       |
| Classification    | Unclassified                                 |
| Associated alerts | 1                                            |
| Lab tag           | `P05-SOC-Lab`                                |

The case interface showed one associated alert and no entities available in the incident graph.

**Validation result:** Case and alert review demonstrated.

## 6. Automation Validation

The captured automation-run histories showed successful executions for:

* `P05 - Tag Invalid Credential Incidents`
* `P05 - Auto-Tag SOC Lab Cases`

Case 513 displayed the expected `P05-SOC-Lab` tag.

**Validation result:** Case-tagging automation execution and resulting case-tag presence verified through captured evidence.

## 7. Investigation-Task Validation

The case contained the task:

`Review Repeated Invalid Credential Attempts`

The task description instructed the analyst to review the affected account and source IP, investigate failed and successful sign-ins, identify suspicious post-authentication activity, and document findings.

| Attribute     | Observed Result |
| ------------- | --------------- |
| Task exists   | Yes             |
| Task priority | High            |
| Task status   | Not set         |
| Case status   | Active          |

**Validation result:** Investigation-task presence verified. Task completion was not established.

## 8. End-to-End Validation Matrix

| Validation item              | Expected evidence                                      | Observed result                                                 | Status        |
| ---------------------------- | ------------------------------------------------------ | --------------------------------------------------------------- | ------------- |
| Authentication query         | Sign-in records returned                               | Results returned                                                | Passed        |
| Outcome summary              | Success, failure, and other-event counts               | 20 total; 11 successful; 6 invalid-credential failures; 3 other | Passed        |
| Result-code analysis         | Result codes and descriptions                          | `0`, `50126`, `50140` visible                                   | Passed        |
| Timeline analysis            | Chronological authentication events                    | Successes and failures visible                                  | Passed        |
| Case review                  | Case and associated alert                              | Case 513; one associated alert                                  | Passed        |
| Case tagging                 | `P05-SOC-Lab` tag                                      | Tag visible on Case 513                                         | Passed        |
| Tag automation               | Successful execution record                            | Successful run shown in captured evidence                       | Passed        |
| Task creation                | Investigation task present                             | Task visible on Case 513                                        | Passed        |
| Task completion              | Completed task state                                   | Status `Not set`                                                | Not verified  |
| Detection threshold match    | At least 3 failures in one qualifying 15-minute window | Not established by aggregate results                            | Not verified  |
| Confirmed malicious activity | Supporting evidence of malicious behavior              | Not established                                                 | Not confirmed |
| Case resolution              | Justified final disposition                            | Case remains Active                                             | Pending       |

## 9. Limitations

* The telemetry represents a specific account, IP address, and query time range.
* The presence of authentication failures does not establish malicious intent.
* The 24-hour aggregate does not establish that the existing 15-minute detection threshold was met.
* The available evidence does not prove that every event in the investigation contributed to Case 513.
* The investigation task remains in the `Not set` state.
* The case remains Active and Unclassified.
* No confirmed account compromise or brute-force attack has been established.

## 10. Evidence References

Evidence is stored under `screenshots/Day15/`.

The relevant evidence set covers:

* Authentication baseline and failed sign-in investigation.
* Failed and successful sign-in correlation.
* Incident and alert review.
* Case management and tag verification.
* Automation execution history.
* Investigation-task creation.
* Authentication result-code analysis.
* Chronological authentication timeline.

Confirm the screenshot filenames before publishing the repository.

## 11. Final Validation Assessment

**Outcome: End-to-end SOC investigation workflow demonstrated.**

The lab demonstrated KQL-based authentication analysis, case and alert review, case-tagging automation, and investigation-task creation.

The evidence supports the recorded telemetry and case-management results. It does not establish a confirmed attack, completion of the investigation task, or resolution of the case.