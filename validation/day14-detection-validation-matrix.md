# Day 14 — Detection Validation Matrix and Measured Metrics

**Project:** Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab
**Day:** 14
**Status:** Completed
**Focus:** Detection validation, controlled testing, measured outcomes, and evidence consolidation
**Environment:** Microsoft Entra ID, Microsoft Defender, and `law-project05-soc`

---

## 1. Executive Summary

Day 14 consolidates the validation results from the authentication detection, endpoint discovery hunting query, SOC automation workflow, and end-to-end investigation completed during Project 05.

The objective was to create a centralized record of test scenarios, expected behavior, observed results, and validation status.

The validation evidence covers real Entra ID telemetry, synthetic KQL testing, controlled Windows endpoint activity, automation execution histories, and Defender case-management evidence.

**Outcome:** The available validation results have been consolidated into a single detection-validation matrix with measurable, evidence-backed outcomes.

---

## 2. Validation Scope

| Validation Area            | Source                                   | Validation Method                                  |
| -------------------------- | ---------------------------------------- | -------------------------------------------------- |
| Authentication detection   | Microsoft Entra ID `SigninLogs`          | Real telemetry and synthetic KQL test              |
| Endpoint discovery hunting | Microsoft Defender `DeviceProcessEvents` | Controlled endpoint command execution              |
| SOC automation             | Microsoft Defender case management       | Automation execution history and case verification |
| End-to-end investigation   | Entra ID sign-in telemetry and Defender  | KQL analysis, case review, and workflow evidence   |

The detailed validation reports remain the authoritative records for each individual test.

---

## 3. Detection Validation Matrix

| ID         | Detection or Workflow                   | Test Method                  | Expected Result                                                      | Observed Result                                             | Status             |
| ---------- | --------------------------------------- | ---------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------ |
| D14-VAL-01 | Repeated Authentication Failures        | Real Entra ID telemetry      | Identify groups meeting the configured threshold                     | No groups met the threshold in the recorded baseline        | Baseline evaluated |
| D14-VAL-02 | Repeated Authentication Failures        | Synthetic KQL test           | Return a group containing at least 3 failures in 15 minutes          | One group containing 4 synthetic failures was returned      | PASS               |
| D14-VAL-03 | Repeated Discovery Activity             | Controlled endpoint test     | Identify matching discovery-related process activity                 | One group containing 2 matching process events was returned | PASS               |
| D14-VAL-04 | Auto-Tag SOC Lab Cases                  | Automation run history       | Record successful execution for an eligible case                     | Successful execution recorded for case 196                  | PASS               |
| D14-VAL-05 | Tag Invalid Credential Incidents        | Automation run history       | Record successful execution for eligible cases                       | Successful executions recorded for cases 195, 196, and 197  | PASS               |
| D14-VAL-06 | End-to-End Authentication Investigation | KQL and Defender case review | Analyze authentication activity and review the related case workflow | 20 sign-in events analyzed and Case 513 reviewed            | Demonstrated       |
| D14-VAL-07 | Investigation Task Verification         | Defender case review         | Verify the investigation task is present                             | Task found on Case 513                                      | PASS               |

**Status definitions**

* **PASS:** The recorded test produced the expected result.
* **Baseline evaluated:** Real telemetry was examined, but no matching detection group was returned.
* **Demonstrated:** The workflow was performed and supported by recorded evidence.

---

## 4. Authentication Detection Metrics

**Detection ID:** `P05-D06-DET-001`
**Detection name:** Repeated Authentication Failures
**Data source:** Microsoft Entra ID `SigninLogs`

### 4.1 Real Telemetry Baseline

| Metric                                    | Observed Result |
| ----------------------------------------- | --------------: |
| Total sign-in records                     |              38 |
| Successful sign-ins                       |              35 |
| Failed sign-ins                           |               3 |
| Unique users                              |               1 |
| Unique source IP addresses                |               5 |
| Matching groups returned by the detection |               0 |

The recorded baseline contained three failed sign-in records. The detection query returned no groups satisfying the configured requirement of at least three failures for the same user and source IP within 15 minutes.

This result describes the observed telemetry and configured query behavior.

### 4.2 Synthetic KQL Test

| Metric                          |                   Result |
| ------------------------------- | -----------------------: |
| Synthetic failed sign-in events |                        4 |
| Synthetic user                  |     `testuser@lab.local` |
| Synthetic IP                    |             `192.0.2.10` |
| Test interval                   |                6 minutes |
| Configured threshold            | 3 failures in 15 minutes |
| Matching groups returned        |                        1 |
| Events in matching group        |                        4 |
| Validation result               |                     PASS |

The synthetic test confirmed that the KQL grouping and threshold logic returned the expected group for the supplied test data.

The test data was generated within the query and did not represent a real attack.

### 4.3 Authentication Detection Summary

The validation demonstrated two distinct outcomes:

1. The real telemetry baseline did not produce a matching detection group.
2. The synthetic test produced one matching group containing four events.

These results should remain separate when reporting detection coverage and test outcomes.

**Detailed report:** `validation/day06-repeated-authentication-failures-validation.md`

---

## 5. Endpoint Discovery Validation Metrics

**Data source:** Microsoft Defender for Endpoint
**Table:** `DeviceProcessEvents`
**Endpoint:** `p05-win10-ep`
**Test account:** `soc-lab-user`

The controlled test executed:

`cmd.exe /c "whoami && hostname"`

### Observed Results

| Metric                       | Result         |
| ---------------------------- | -------------- |
| Controlled command execution | Successful     |
| Endpoint identified          | `p05-win10-ep` |
| Account identified           | `soc-lab-user` |
| Matching process events      | 2              |
| Matching groups returned     | 1              |
| Hunting query result         | PASS           |

The query identified matching discovery-related process activity in the available Defender telemetry.

The test demonstrated query behavior against controlled endpoint activity. It did not establish malicious behavior.

**Detailed report:** `validation/day07-repeated-discovery-validation.md`

---

## 6. SOC Automation Metrics

The automation validation recorded successful execution histories for two case-tagging rules.

| Automation Rule                          | Case ID | Recorded Execution Result |
| ---------------------------------------- | ------: | ------------------------- |
| `P05 - Auto-Tag SOC Lab Cases`           |     196 | Success                   |
| `P05 - Tag Invalid Credential Incidents` |     195 | Success                   |
| `P05 - Tag Invalid Credential Incidents` |     196 | Success                   |
| `P05 - Tag Invalid Credential Incidents` |     197 | Success                   |

### Consolidated Automation Results

| Metric                                 | Recorded Result |
| -------------------------------------- | --------------: |
| Automation rules covered               |               2 |
| Displayed successful execution records |               4 |
| Distinct case IDs in these records     |               3 |
| Expected lab tag                       |   `P05-SOC-Lab` |
| Investigation task configuration       |      Documented |

These counts describe the displayed records in the existing validation report. They are not a measurement of overall automation reliability or a guarantee that every future case will be processed successfully.

**Detailed report:** `validation/day13-automation-validation.md`

---

## 7. End-to-End Investigation Metrics

The Day 15 investigation analyzed sign-in telemetry for a selected account and source IP over a 24-hour period.

### Observed Authentication Results

| Metric                      | Result |
| --------------------------- | -----: |
| Total sign-in events        |     20 |
| Successful sign-ins         |     11 |
| Invalid-credential failures |      6 |
| Other events                |      3 |

The results reconcile:

**11 successful + 6 invalid-credential failures + 3 other events = 20 total events.**

### Defender Case Results

| Attribute               | Observed Result                              |
| ----------------------- | -------------------------------------------- |
| Case ID                 | 513                                          |
| Case name               | `P05 - Repeated Invalid Credential Attempts` |
| Severity                | Low                                          |
| Status                  | Active                                       |
| Classification          | Unclassified                                 |
| Associated alerts shown | 1                                            |
| Lab tag                 | `P05-SOC-Lab`                                |
| Investigation task      | Present                                      |

The investigation demonstrated authentication analysis, case review, tag verification, and task verification.

The 24-hour aggregate of six invalid-credential failures does not independently establish that the Day 06 detection threshold was met within a single 15-minute window.

**Detailed report:** `validation/day15-end-to-end-investigation-validation.md`

---

## 8. Consolidated Quantitative Summary

| Measurement                                       | Recorded Value | Source            |
| ------------------------------------------------- | -------------: | ----------------- |
| Real authentication records in Day 06 baseline    |             38 | Day 06 validation |
| Real failed sign-in records in Day 06 baseline    |              3 | Day 06 validation |
| Synthetic authentication events tested            |              4 | Day 06 validation |
| Synthetic matching groups returned                |              1 | Day 06 validation |
| Matching discovery process events                 |              2 | Day 07 validation |
| Automation rules covered                          |              2 | Day 13 validation |
| Successful automation execution records displayed |              4 | Day 13 validation |
| Distinct case IDs in those execution records      |              3 | Day 13 validation |
| Sign-in events analyzed during Day 15             |             20 | Day 15 validation |
| Day 15 successful sign-ins                        |             11 | Day 15 validation |
| Day 15 invalid-credential failures                |              6 | Day 15 validation |
| Day 15 other events                               |              3 | Day 15 validation |

### Interpreting the Metrics

These figures measure different things:

* **Events** measure individual records in the relevant query scope.
* **Matching groups** measure grouped results returned by a query.
* **Execution records** measure recorded automation runs.
* **Distinct case IDs** measure the number of unique cases represented by those runs.

They should not be added together or combined into a single overall success percentage.

---

## 9. Evidence and Report Index

| Validation Area          | Detailed Report                                                   |
| ------------------------ | ----------------------------------------------------------------- |
| Authentication detection | `validation/day06-repeated-authentication-failures-validation.md` |
| Endpoint discovery       | `validation/day07-repeated-discovery-validation.md`               |
| SOC automation           | `validation/day13-automation-validation.md`                       |
| End-to-end investigation | `validation/day15-end-to-end-investigation-validation.md`         |

Supporting evidence is maintained in the corresponding directories under `screenshots/Day06/`, `screenshots/Day07/`, `screenshots/Day13/`, and `screenshots/Day15/`.

The detailed reports contain the test-specific screenshots, procedures, observed results, and validation context.

---

## 10. Day 14 Completion Summary

| Deliverable                                    | Status    |
| ---------------------------------------------- | --------- |
| Existing detection-validation reports reviewed | Completed |
| Authentication detection metrics consolidated  | Completed |
| Synthetic KQL test results documented          | Completed |
| Endpoint discovery validation consolidated     | Completed |
| Automation execution metrics consolidated      | Completed |
| Day 15 investigation metrics included          | Completed |
| Evidence references organized                  | Completed |
| Detection validation matrix documented         | Completed |
| Quantitative results reconciled                | Completed |

## Conclusion

Day 14 consolidated the available detection and workflow validation evidence from Project 05 into a centralized matrix.

The documented results include authentication baseline analysis, synthetic detection testing, controlled endpoint discovery validation, successful automation execution records, and end-to-end authentication investigation metrics.

The matrix provides a traceable summary of the observed test outcomes while preserving the distinction between real telemetry, synthetic test data, controlled endpoint activity, and case-management evidence.

**Day 14 Status: COMPLETED**
