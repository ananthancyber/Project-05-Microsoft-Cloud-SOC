# Day 07 — Repeated Discovery Activity Validation

## 1. Objective

Validate a KQL hunting query that identifies repeated discovery-related command execution on the P05 Windows endpoint using Microsoft Defender for Endpoint telemetry.

## 2. Environment

| Field | Value |
|---|---|
| Project | Project 05 — Microsoft Cloud SOC |
| Endpoint | `p05-win10-ep` |
| Test account | `soc-lab-user` |
| Data source | Microsoft Defender for Endpoint |
| Advanced Hunting table | `DeviceProcessEvents` |
| Query file | `kql/endpoint/day07-repeated-discovery-activity.kql` |

## 3. Detection Logic

The query searches for process events containing discovery-related command strings, including:

- `whoami`
- `hostname`
- `ipconfig`
- `systeminfo`
- `net user`
- `net localgroup`

Matching events are grouped by device, account, and 15-minute time bucket.

The query returns groups containing at least two matching process events.

## 4. Controlled Test Scenario

Executed the following command on the P05 Windows endpoint:

`cmd.exe /c "whoami && hostname"`

The command displayed the current user and computer name without modifying system configuration.

### Observed output

- User: `soc-lab-user`
- Hostname: `p05-win10-ep`

## 5. Validation Results

| Validation item | Observed result |
|---|---|
| Controlled command executed | Pass |
| Process event located in Defender | Pass |
| Endpoint identified | Pass |
| Account identified | Pass |
| Parent process identified | Pass |
| Discovery-related query returned a matching group | Pass |
| Matching event group count | 2 |

The repeated-discovery query returned one group containing two matching process events for `p05-win10-ep` and `soc-lab-user`.

The observed command strings included:

- `cmd.exe /c "whoami && hostname"`
- `whoami`

## 6. Interpretation

The results demonstrate that the hunting query can identify matching discovery-related process activity in the available Defender telemetry.

The observed commands are legitimate administrative commands. The result validates the query against the controlled test scenario; it does not demonstrate a real attack or confirm malicious activity.

## 7. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1082 | System Information Discovery | The test included `hostname`, which can be used to identify the system. |
| T1033 | System Owner/User Discovery | The test included `whoami`, which identifies the current user. |

These mappings describe the behaviors represented by the commands, not evidence of an attack.

## 8. Evidence

Store the corresponding screenshots in `screenshots/Day07/`.

- `Day07-09-CMD-Process-Execution.png` — controlled Windows command execution.
- `Day07-10-CMD-Process-Telemetry-Validation.png` — matching process event in Defender.
- `Day07-11-CMD-Whoami-Detection-Validation.png` — targeted hunting query validation.
- `Day07-12-Endpoint-Discovery-Hunt-Validation.png` — repeated-discovery query results.

Confirm that the filenames match the actual screenshots in the repository.

## 9. Outcome

A reusable KQL hunting query was created and validated against controlled endpoint activity.

The query provides a starting point for investigating repeated discovery-related commands. Further tuning and testing are required before treating it as a production detection.