# Hunt 02 — Suspicious PowerShell Execution

## 1. Hypothesis
PowerShell may have been used to execute suspicious commands or perform potentially malicious activity on the monitored endpoint.

## 2. Data Source
- Platform: Microsoft Defender Advanced Hunting
- Table: `DeviceProcessEvents`
- Endpoint: `p05-win10-ep`

## 3. Investigation
Existing Day 09 process and PowerShell investigations were reviewed.

Evidence references:
- `screenshots/Day09/Day09-02-Suspicious-Process-Pattern-Hunt.png`
- `screenshots/Day09/Day09-03-Process-Execution-Investigation.png`
- `screenshots/Day09/Day09-06-PowerShell-Command-Line-Investigation.png`
- `screenshots/Day09/Day09-07-PowerShell-Full-Command-Line.png`

## 4. Observation
Previously collected process and PowerShell telemetry is available for investigation.

Record specific suspicious commands, parent processes, execution patterns, or other relevant findings only when supported by the saved query results.

## 5. Conclusion
The hypothesis must be evaluated using the actual process and command-line evidence. PowerShell usage alone does not establish malicious activity.

## 6. Next Action
- Review any suspicious command lines and their parent processes.
- Determine whether the activity is consistent with expected administrative or user behavior.
- Record any unresolved findings for further investigation.

## 7. Status
Pending evidence-based conclusion from the existing investigation results.