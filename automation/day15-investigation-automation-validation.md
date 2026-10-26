# Day 15 — Investigation Automation Validation

## 1. Overview

| Field           | Details                                                    |
| --------------- | ---------------------------------------------------------- |
| Project         | Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab |
| Day             | 15                                                         |
| Artifact ID     | P05-D15-AUTO-001                                           |
| Platform        | Microsoft Defender case management                         |
| Environment     | `law-project05-soc`                                        |
| Focus           | Case tagging and investigation-task creation               |
| Related Case    | 513                                                        |
| Validation Type | Execution-history and case-state verification              |

## 2. Objective

Validate the case-management automation used during the Day 15 end-to-end authentication investigation.

The validation focuses on whether the configured automation rules executed successfully and whether the resulting case contains the expected lab tag and investigation task.

This artifact supplements the existing Day 13 automation documentation. It does not replace the original rule configurations or their historical execution records.

## 3. Automation Rules

### 3.1 P05 - Tag Invalid Credential Incidents

**Purpose:** Apply a consistent lab-identification tag to eligible cases associated with the repeated-invalid-credential detection.

| Setting             | Value                                              |
| ------------------- | -------------------------------------------------- |
| Rule name           | `P05 - Tag Invalid Credential Incidents`           |
| Action              | Update case                                        |
| Expected tag        | `P05-SOC-Lab`                                      |
| Day 15 verification | Successful execution shown in captured run history |

### 3.2 P05 - Auto-Tag SOC Lab Cases

**Purpose:** Apply the lab-identification tag to eligible lab cases.

| Setting             | Value                                              |
| ------------------- | -------------------------------------------------- |
| Rule name           | `P05 - Auto-Tag SOC Lab Cases`                     |
| Action              | Update case                                        |
| Expected tag        | `P05-SOC-Lab`                                      |
| Day 15 verification | Successful execution shown in captured run history |

The original configuration details and rule conditions are documented in:

`automation/day13-automation-rules.md`

## 4. Validation Method

The Day 15 validation used the following procedure:

1. Opened the Microsoft Defender case associated with the authentication alert.
2. Identified Case 513.
3. Reviewed the case tag.
4. Opened the case's Tasks panel.
5. Verified the investigation task.
6. Reviewed the captured automation run histories for the tagging and task-creation rules.

The validation is based on the configuration and execution evidence captured during the lab.

## 5. Execution Results

The captured automation run histories showed successful executions of both tagging rules.

| Automation                               | Evidence result            |
| ---------------------------------------- | -------------------------- |
| `P05 - Tag Invalid Credential Incidents` | Successful execution shown |
| `P05 - Auto-Tag SOC Lab Cases`           | Successful execution shown |

The previously captured Day 13 evidence includes successful runs for case IDs 195, 196, and 197. The Day 15 evidence includes successful runs for Case 513 and other cases visible in the execution history.

A successful automation run establishes that the recorded action executed successfully. It does not, by itself, establish that the underlying authentication activity was malicious.

## 6. Case-State Verification

The Day 15 case review confirmed the following state for Case 513:

| Field             | Observed result                              |
| ----------------- | -------------------------------------------- |
| Case ID           | `513`                                        |
| Case title        | `P05 - Repeated Invalid Credential Attempts` |
| Severity          | Low                                          |
| Case status       | Active                                       |
| Classification    | Unclassified                                 |
| Associated alerts | 1                                            |
| Lab tag           | `P05-SOC-Lab`                                |

The case displayed the expected lab tag.

## 7. Investigation-Task Verification

The following task was present in Case 513:

**Task name:** `Review Repeated Invalid Credential Attempts`

The task description directs the analyst to review the affected account and source IP, investigate failed and successful sign-ins, identify suspicious post-authentication activity, and document findings.

| Task attribute   | Observed result |
| ---------------- | --------------- |
| Task exists      | Yes             |
| Task status      | Not set         |
| Task priority    | High            |
| Task description | Present         |

The task's presence demonstrates task creation. Its status of `Not set` means the evidence does not establish task completion.

## 8. Validation Assessment

**Result: Case-tagging and task-creation workflow demonstrated.**

The captured evidence supports the following conclusions:

* Both tagging rules have successful execution records.
* Case 513 contains the `P05-SOC-Lab` tag.
* Case 513 contains the expected investigation task.
* The automation and case state can be inspected using the captured execution history and case interface.

The evidence does not establish that the investigation task was completed, that Case 513 was resolved, or that the associated authentication activity was malicious.

## 9. Evidence References

The original Day 13 configuration and execution evidence is stored under:

`screenshots/Day13/`

The Day 15 case and automation evidence is stored under:

`screenshots/Day15/`

Relevant Day 15 screenshots include:

* `Day15-08-Automated-Investigation-Task.png`
* `Day15-09-Tag-Automation-Execution-Success.png`
* `Day15-10-Task-Automation-Execution-Success.png`
* `Day15-11-Case-Tag-And-Task-Verification.png`
* `Day15-15-Final-Case-Task-Verification.png`

Confirm that these filenames match the files in your repository before publishing this artifact.

## 10. Conclusion

Day 15 provides evidence that the SOC case-management workflow supports automated case tagging and investigation-task creation.

Case 513 was verified to contain the expected lab tag and investigation task, and the captured execution histories showed successful automation runs.

**Final result:** Automation execution verified through captured evidence; case tag and task presence confirmed.
