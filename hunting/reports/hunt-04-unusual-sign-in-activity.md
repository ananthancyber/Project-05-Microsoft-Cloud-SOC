# Hunt 04 — Unusual Sign-In Activity

## 1. Hypothesis
Sign-in activity may contain unusual authentication failures, source IP patterns, or application access that warrants further investigation.

## 2. Data Source
- Platform: Microsoft Sentinel
- Table: `SigninLogs`
- Time Window: Last 7 days

## 3. Investigation
Existing Day 09 sign-in investigations were reviewed.

The collected telemetry includes:
- 54 sign-in events for one Entra ID account.
- 51 successful sign-ins.
- 3 failed sign-ins.
- 9 distinct source IPs in the seven-day summary.

Previously investigated failure codes include:
- `50140` — the recorded description indicates a "Keep me signed in" interruption.
- `500014` — the recorded description references a service principal issue.

These failure codes must be interpreted in their event context rather than treated as proof of an attack.

## 4. Observation
The available results show sign-in activity from multiple source IPs and a small number of failed attempts.

The available evidence does not, by itself, establish that the sign-ins were malicious or that the account was compromised.

## 5. Conclusion
The hypothesis identified authentication events worth reviewing, but malicious activity has not been established.

## 6. Next Action
- Compare source IPs, applications, timestamps, and authentication outcomes with expected activity.
- Investigate any genuinely unexplained sign-ins using available event details.
- Escalate only when supporting evidence justifies further action.

## 7. Evidence
- `screenshots/Day09/Day09-08-Signin-Telemetry-Baseline.png`
- `screenshots/Day09/Day09-09-Unusual-Signin-Activity-Summary.png`
- `screenshots/Day09/Day09-10-Failed-Signin-Investigation.png`
- `screenshots/Day09/Day09-11-Azure-Portal-Failure-Analysis.png`
- `screenshots/Day09/Day09-12-Azure-Portal-Authentication-Details.png`
- `screenshots/Day09/Day09-13-SignIn-IP-Investigation.png`

## 8. Status
Investigated — no confirmed malicious sign-in activity established by the available evidence.