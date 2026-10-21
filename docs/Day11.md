# Day 11 — Endpoint Incident Investigation

## 1. Overview

**Project:** Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab  
**Day:** 11 of 18  
**Focus:** Endpoint Incident Investigation  
**Platform:** Microsoft Defender for Endpoint  
**Investigation Environment:** Microsoft Defender Advanced Hunting  
**Endpoint:** `p05-win10-ep`  
**User Account:** `soc-lab-user`  
**Operating System:** Windows 10 64-bit  
**Simulation:** `Project05-Day11-IncidentSimulation`

## 2. Objective

The objective of Day 11 was to investigate controlled endpoint discovery activity using Microsoft Defender telemetry.

The investigation focused on understanding process execution, reviewing PowerShell activity, examining process relationships, identifying the account associated with observed events, and assessing whether the activity was consistent with the intended lab simulation.

This exercise follows a practical SOC investigation workflow:

1. Establish the endpoint baseline.
2. Review endpoint process telemetry.
3. Investigate process execution activity.
4. Examine PowerShell execution and process relationships.
5. Review discovery-related activity.
6. Establish the available identity context.
7. Assess the evidence and document the investigation findings.

## 3. Lab Environment

| Component | Details |
|---|---|
| Endpoint | `p05-win10-ep` |
| Operating system | Windows 10 64-bit |
| Security platform | Microsoft Defender for Endpoint |
| Investigation interface | Microsoft Defender Advanced Hunting |
| Primary telemetry table | `DeviceProcessEvents` |
| User account observed | `soc-lab-user` |
| Activity type | Controlled endpoint discovery simulation |

The investigation used endpoint process telemetry to examine recorded execution events and their associated process context.

## 4. Investigation Methodology

### 4.1 Endpoint Baseline

The investigation began by reviewing the endpoint's available telemetry and establishing the system being investigated.

This step provides context for subsequent process investigations and helps ensure that queries are scoped to the intended lab endpoint.

**Evidence:**

![Day 11 endpoint baseline](../screenshots/Day11/Day11-01-Endpoint-Baseline.png)

*Figure 1 — Endpoint baseline in Microsoft Defender Advanced Hunting.*

### 4.2 Endpoint Process Telemetry

The next step was to inspect process execution telemetry associated with the lab endpoint.

The `DeviceProcessEvents` table was used to examine recorded process activity. Relevant fields included the timestamp, device name, account name, executable name, command line, and initiating process information.

These fields help an analyst understand what executed, when it executed, and which process initiated it.

**Evidence:**

![Day 11 endpoint process telemetry](../screenshots/Day11/Day11-02-Endpoint-Process-Telemetry.png)

*Figure 2 — Endpoint process telemetry reviewed during the investigation.*

### 4.3 Process Activity Baseline

Process activity was reviewed to establish context around the executables observed on the endpoint.

A process appearing frequently in telemetry is not automatically suspicious. Analysts should consider the executable, its command line, its parent process, the associated account, and the surrounding activity before reaching a conclusion.

**Evidence:**

![Day 11 process activity baseline](../screenshots/Day11/Day11-03-Process-Activity-Baseline.png)

*Figure 3 — Process activity baseline used to provide context for the investigation.*

### 4.4 PowerShell Incident Execution

PowerShell activity associated with the controlled simulation was investigated using endpoint process telemetry.

The investigation examined the relationship between Windows Explorer and PowerShell and reviewed the available executable metadata.

The evidence showed the following process relationship:

`explorer.exe → powershell.exe`

The inspected PowerShell executable was located at:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

Microsoft Windows was displayed as the executable's signer. The screenshot also showed a VirusTotal detection ratio of `0/71`.

These observations provide useful context, but a valid digital signature or a zero-detection ratio does not independently establish that every action performed by the process was benign.

**Evidence:**

![Day 11 PowerShell incident execution](../screenshots/Day11/Day11-04-PowerShell-Incident-Execution.png)

*Figure 4 — PowerShell execution and process-tree context examined in Microsoft Defender.*

### 4.5 Endpoint Discovery Simulation

The lab included controlled discovery commands such as `whoami`, `ipconfig`, and `Get-Process`.

These commands can be used during legitimate administration and security investigations, but similar commands can also appear during attacker reconnaissance.

Their presence must therefore be evaluated in context rather than treated as conclusive evidence of compromise.

The simulation activity was intentionally generated as part of this lab exercise.

**Evidence:**

![Day 11 endpoint discovery simulation](../screenshots/Day11/Day11-06-Endpoint-Discovery-Simulation.png)

*Figure 5 — Controlled endpoint discovery activity performed during the simulation.*

### 4.6 Identity Context and Process Tree

The investigation reviewed the identity context associated with recorded endpoint activity.

The inspected event showed:

- **Device:** `p05-win10-ep`
- **Account:** `soc-lab-user`
- **Observed process:** `powershell.exe`
- **Child process:** `whoami.exe`

The available process-tree evidence showed:

`explorer.exe → powershell.exe → whoami.exe`

The `whoami.exe` utility displays the identity of the account running a process. Its execution is not inherently malicious.

The account and process context were used to interpret the observed activity within the controlled simulation.

**Evidence:**

![Day 11 identity context discovery](../screenshots/Day11/Day11-07-Identity-Context-Discovery.png)

*Figure 6 — Identity context and process-tree information reviewed during the investigation.*

## 5. Investigation Findings

The following findings are based on the screenshots and observations collected during the lab exercise.

| ID | Finding | Assessment |
|---|---|---|
| F-01 | Endpoint process telemetry was available for `p05-win10-ep`. | Endpoint telemetry reviewed. |
| F-02 | PowerShell execution was observed during the controlled simulation. | Consistent with the intended lab activity. |
| F-03 | The inspected process tree showed `explorer.exe` launching `powershell.exe`. | Process relationship observed. |
| F-04 | The inspected discovery activity included `whoami.exe`. | Consistent with identity discovery. |
| F-05 | The inspected PowerShell executable was Microsoft-signed. | Signature information observed; not proof that all activity was benign. |
| F-06 | The displayed VirusTotal detection ratio was `0/71`. | No detections were displayed in the captured report; this does not guarantee safety. |
| F-07 | The discovery commands were intentionally executed as part of the lab simulation. | Confirmed by the lab operator. |

## 6. Incident Assessment

### Assessment: Controlled Lab Activity

The activity examined during this exercise was intentionally generated as part of the Day 11 endpoint simulation.

The observed PowerShell and discovery commands were consistent with the stated simulation objective. The reviewed screenshots do not, by themselves, establish that a real endpoint compromise occurred.

This conclusion is limited to the activity and evidence reviewed. It is not a claim that the endpoint was comprehensively proven free of malicious activity.

### Important Investigation Limitations

The available evidence does not independently establish:

- That every process executed during the simulation has been reviewed.
- That all potentially relevant endpoint events have been correlated.
- That no other suspicious activity occurred on the endpoint.
- That every discovery command completed successfully.
- That a security incident was detected, escalated, or contained by an automated response.

These limitations should remain explicit in the investigation record.

## 7. Recommended SOC Response

In a real SOC investigation involving similar activity, an analyst should:

1. **Validate the alert or investigation trigger.** Establish why the activity was investigated and identify the relevant detection or report.
2. **Inspect the complete process context.** Review parent and child processes, command lines, executable paths, signatures, and relevant timestamps.
3. **Validate the user context.** Determine whether the account and activity align with expected administrative or user behavior.
4. **Correlate related telemetry.** Examine relevant authentication, endpoint, network, and other security events where available.
5. **Assess impact and scope.** Determine whether the activity affected other processes, accounts, or devices.
6. **Make a defensible decision.** Classify the activity using the available evidence and record unresolved questions.
7. **Follow the response procedure.** If evidence supports a genuine threat, escalate and perform authorized containment and remediation according to organizational policy.

These are recommended response steps, not actions claimed to have been performed during this lab exercise.

## 8. Evidence Register

All six screenshots are stored in the repository under `screenshots/Day11/`.

| Evidence ID | Filename | Purpose |
|---|---|---|
| E-01 | `Day11-01-Endpoint-Baseline.png` | Endpoint baseline |
| E-02 | `Day11-02-Endpoint-Process-Telemetry.png` | Process telemetry |
| E-03 | `Day11-03-Process-Activity-Baseline.png` | Process activity baseline |
| E-04 | `Day11-04-PowerShell-Incident-Execution.png` | PowerShell execution and process-tree evidence |
| E-05 | `Day11-06-Endpoint-Discovery-Simulation.png` | Controlled discovery simulation |
| E-06 | `Day11-07-Identity-Context-Discovery.png` | Identity context and process-tree evidence |

**Evidence note:** The screenshot numbering skips `Day11-05`. Existing filenames have been preserved to maintain consistency with the evidence already captured.

## 9. Skills Practiced

This exercise provided practical experience with:

- Microsoft Defender Advanced Hunting.
- KQL-based endpoint telemetry investigation.
- Windows process execution analysis.
- PowerShell investigation.
- Parent-child process relationships.
- User and endpoint context analysis.
- Controlled discovery simulation.
- Evidence interpretation and documentation.
- Writing evidence-based investigation conclusions.
- Identifying limitations in an incident assessment.

## 10. Conclusion

Day 11 focused on investigating controlled endpoint discovery activity using Microsoft Defender telemetry.

The collected evidence documents endpoint process activity, PowerShell execution, process-tree relationships, and identity context associated with the simulation.

The observations were consistent with the intended lab activity, and the available evidence did not establish a real compromise. The investigation also demonstrates why SOC analysts must distinguish observed facts from assumptions and avoid treating individual commands, digital signatures, or reputation results as conclusive evidence.

The next step in the project is to continue with the planned incident-response and containment work, using the findings from this investigation as context.

---

**Project:** Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab  
**Day 11 Status:** Investigation evidence collected; findings documented  
**Environment:** Authorized personal cybersecurity lab