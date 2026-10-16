# Hunt 01 — Password Spraying Across Multiple Accounts

## 1. Hypothesis
A single source IP may be attempting to authenticate against multiple user accounts using repeated failed sign-ins.

## 2. Data Source
- Platform: Microsoft Sentinel
- Table: `SigninLogs`
- Time Window: Last 7 days

## 3. Hunting Query
The query is maintained in `hunting/day09-threat-hunting-queries.kql`.

The hunt groups failed sign-ins by source IP and counts the distinct accounts targeted. It filters for source IPs associated with failures against at least three distinct accounts.

## 4. Observation
The query returned zero matching results.

The available sign-in telemetry currently shows activity for one distinct Entra ID account:
`ananthan@personalcybersecuritylab.onmicrosoft.com`

The absence of matching results means the hypothesis was not validated by this query.

## 5. Conclusion
No password-spraying pattern targeting at least three distinct accounts was identified in the available results.

This is an inconclusive finding, not proof that password spraying did not occur. The current account coverage limits the investigation.

## 6. Next Action
- Retain the query for future use if additional accounts become available.
- Continue investigating other hypotheses supported by existing telemetry.
- Do not classify the observed authentication failures as malicious without additional evidence.

## 7. Evidence
- Screenshot: `screenshots/Day09/Day09-09-Unusual-Signin-Activity-Summary.png`
- Screenshot: `screenshots/Day09/Day09-10-Failed-Signin-Investigation.png`

## 8. Status
**Inconclusive — no matching password-spray pattern identified.**