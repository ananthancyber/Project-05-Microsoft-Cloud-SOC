# Day 15 — Authentication Incident Investigation

## 1. Investigation Overview

| Field                | Details                                                    |
| -------------------- | ---------------------------------------------------------- |
| Project              | Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab |
| Day                  | 15                                                         |
| Investigation ID     | P05-D15-INV-001                                            |
| Investigation Type   | Authentication Incident Investigation                      |
| Platform             | Microsoft Defender and Microsoft Entra ID                  |
| Data Source          | Microsoft Entra ID sign-in logs                            |
| Log Table            | `SigninLogs`                                               |
| Query Language       | Kusto Query Language (KQL)                                 |
| Related Detection    | `P05-D06-DET-001`                                          |
| Defender Case ID     | 513                                                        |
| Investigation Status | Investigation performed; further validation pending        |

## 2. Investigation Objective

The objective was to demonstrate an end-to-end SOC investigation workflow using Microsoft Entra ID authentication telemetry and Microsoft Defender case management.

The investigation focused on:

* Reviewing authentication activity for a specific lab account and source IP.
* Identifying failed and successful sign-in events.
* Examining authentication result codes and event timestamps.
* Reviewing the associated Defender case and alert.
* Verifying case-tagging and investigation-task automation.
* Recording findings and determining an evidence-based investigation disposition.

The activity was investigated in a controlled lab environment. The presence of failed sign-ins was not treated as proof of a confirmed attack.

## 3. Investigation Scope

The KQL investigation used a 24-hour lookback and filtered events by the following account and IP address.

| Attribute              | Observed Value                                      |
| ---------------------- | --------------------------------------------------- |
| User principal name    | `ananthan@personalcybersecuritylab.onmicrosoft.com` |
| Source IP address      | `157.51.230.238`                                    |
| Location shown in logs | India (`IN`)                                        |
| Applications observed  | Azure Portal; Office365 Shell WCSS-Client           |
| Data table             | `SigninLogs`                                        |

These findings apply to the selected account, IP address, and query time range. They do not establish the nature of activity outside this scope.

## 4. Investigation Workflow

The investigation followed these stages:

1. Reviewed baseline authentication telemetry.
2. Queried failed sign-in events.
3. Correlated failed and successful sign-ins for the selected account and IP.
4. Summarized authentication outcomes.
5. Examined authentication result codes and descriptions.
6. Reviewed the associated Defender case and alert.
7. Verified case-tagging and task-creation automation.
8. Recorded the investigation assessment and outstanding follow-up actions.

## 5. KQL Investigation

The investigation queries are maintained in:

`kql/authentication/day15-end-to-end-investigation.kql`

The file contains queries for:

* Authentication event timelines.
* Authentication outcome summaries.
* Authentication result-code breakdowns.

### Investigation approach

The queries filter the `SigninLogs` table by the selected account and source IP. They project timestamps, result codes, result descriptions, application names, and location information.

The event timeline is ordered chronologically to support investigation of the sequence of authentication successes and failures.

The summary query measures observed activity within the selected 24-hour period.

## 6. Authentication Investigation Results

The outcome-summary query returned the following results during the investigation.

| Metric                                                | Observed Result |
| ----------------------------------------------------- | --------------: |
| Total sign-in events                                  |              20 |
| Successful sign-ins (`ResultType == "0"`)             |              11 |
| Invalid-credential failures (`ResultType == "50126"`) |               6 |
| Other events                                          |               3 |

The result-code analysis displayed these categories:

| Result code | Description                                                      | Interpretation                                    |
| ----------- | ---------------------------------------------------------------- | ------------------------------------------------- |
| `0`         | Successful sign-in                                               | Authentication succeeded                          |
| `50126`     | Error validating credentials due to invalid username or password | Invalid-credential failure                        |
| `50140`     | Interruption associated with the "Keep me signed in" prompt      | Sign-in interruption; not automatically malicious |

The result-code summary showed the available categories but did not display the event count for each category in the captured view. The distribution of the three other events should not be inferred from that screenshot alone.

These figures describe the observed query results at the time of investigation. They may change as additional telemetry arrives or the lookback window advances.

## 7. Authentication Timeline Analysis

The chronological query showed the following sequence among the visible events:

1. A successful Azure Portal sign-in.
2. Two failed Azure Portal sign-ins with result code `50126`.
3. Subsequent successful Azure Portal sign-ins.
4. Successful sign-ins associated with Office365 Shell WCSS-Client.

The two visible invalid-credential failures occurred approximately 78 seconds apart.

The reviewed events were associated with the same account and source IP.

### Analyst Interpretation

The sequence warrants investigation because invalid-credential failures occurred alongside successful sign-ins for the same account and IP.

However, the available evidence does not establish that:

* An attacker generated the failed sign-ins.
* A brute-force attack occurred.
* The account was compromised.
* The successful sign-ins were performed by an unauthorized person.
* Every event in the KQL timeline contributed to the associated Defender case.

The findings are therefore recorded as observed authentication activity requiring appropriate contextual validation, rather than a confirmed malicious incident.

## 8. Related Detection

| Field                 | Details                                                                                     |
| --------------------- | ------------------------------------------------------------------------------------------- |
| Detection ID          | `P05-D06-DET-001`                                                                           |
| Detection Name        | Repeated Authentication Failures                                                            |
| Detection Time Window | 15 minutes                                                                                  |
| Detection Threshold   | At least 3 failed sign-in records for the same user and source IP within a 15-minute window |
| MITRE ATT&CK Mapping  | T1110 — Brute Force                                                                         |

The detection logic and validation evidence are documented in:

`detections/day06-repeated-authentication-failures.md`

The existing detection was tested against real Entra ID telemetry and synthetic data. Its synthetic test demonstrated the configured grouping and threshold logic.

The Day 15 investigation observed six invalid-credential failures across the selected 24-hour scope. This aggregate count does not demonstrate that three or more failures occurred within a single qualifying 15-minute window.

The Day 15 investigation should not be described as a confirmed match for the existing detection unless the matching query results or alert evidence establish that relationship.

## 9. Defender Case Review

The investigation included a review of Defender Case 513.

| Field             | Observed Value                               |
| ----------------- | -------------------------------------------- |
| Case ID           | `513`                                        |
| Case name         | `P05 - Repeated Invalid Credential Attempts` |
| Severity          | Low                                          |
| Status            | Active                                       |
| Classification    | Unclassified                                 |
| Associated alerts | 1                                            |
| Lab tag           | `P05-SOC-Lab`                                |

The case page showed one associated alert. The incident graph indicated that no entities were available to display.

The case and alert were reviewed as part of the investigation workflow. The available evidence does not independently establish that every event in the KQL timeline contributed to this case.

## 10. Case Management and Automation

The lab includes automation for tagging relevant cases and creating investigation tasks.

### 10.1 Case-tagging automation

The automation rule `P05 - Tag Invalid Credential Incidents` was previously executed successfully, according to the captured automation-run evidence.

The case displayed the tag:

`P05-SOC-Lab`

### 10.2 Investigation-task automation

The automation rule `P05 - Auto-Tag SOC Lab Cases` was previously executed successfully, according to the captured automation-run evidence.

Case 513 contained the task:

**Review Repeated Invalid Credential Attempts**

The task description instructed the analyst to:

* Review the affected account and source IP.
* Investigate failed and successful sign-ins.
* Identify suspicious post-authentication activity.
* Document the investigation findings.

### 10.3 Task and case status

At the time of the captured evidence:

* The investigation task was present.
* The task status was `Not set`.
* The case remained Active.
* The case classification remained Unclassified.

The evidence demonstrates task creation and case tagging. It does not demonstrate that the task was completed or that the case was resolved.

## 11. Investigation Assessment

**Assessment:** Authentication activity investigated; malicious activity not confirmed.

The investigation demonstrated KQL-based analysis of authentication telemetry, review of an associated Defender case and alert, and verification of case-management automation.

The observed telemetry contained both invalid-credential failures and successful sign-ins for the same account and source IP. The available evidence is insufficient to conclude that a brute-force attack or account compromise occurred.

The case remains Active and Unclassified pending further validation. This disposition reflects the current evidence and the outstanding investigation task.

## 12. Recommended Follow-Up

The following actions would provide additional context before a final case disposition:

1. Review the full sign-in details for the relevant events.
2. Determine whether the authentication activity is consistent with expected lab-account usage.
3. Examine related identity activity and post-authentication events where telemetry is available.
4. Verify whether any individual 15-minute window satisfies the existing detection threshold.
5. Update the case findings and classification when sufficient evidence is available.
6. Complete the investigation task and follow the lab's documented case-closure process when justified.

These are recommended follow-up actions, not actions claimed to have been completed.

## 13. Evidence References

The supporting screenshots are stored under:

`screenshots/Day15/`

The evidence set includes screenshots covering:

* Authentication telemetry baseline.
* Failed sign-in investigation.
* Failed and successful sign-in correlation.
* Authentication incident inventory.
* Incident details and associated alert.
* Case management.
* Automated investigation-task creation.
* Case-tagging automation execution.
* Task-creation automation execution.
* Case tag and task verification.
* Authentication investigation findings.
* Result-code analysis.
* Chronological authentication timeline.
* Final Case 513 task verification.

Verify the actual filenames in `screenshots/Day15/` before publishing the repository. Use relative paths to the confirmed filenames if you add direct links to individual screenshots.

## 14. Conclusion

Day 15 demonstrates an end-to-end SOC investigation workflow using Microsoft Entra ID sign-in telemetry and Microsoft Defender case management.

The work covered KQL-based authentication analysis, result-code investigation, chronological event review, case and alert inspection, case tagging, and automated investigation-task creation.

The investigation recorded measurable telemetry results and preserved the distinction between suspicious authentication behavior and a confirmed attack.

**Final outcome:** Investigation workflow demonstrated; case-tagging and task-creation automation verified through captured evidence; malicious activity not confirmed.
