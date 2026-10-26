# Detection: Repeated Authentication Failures

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | P05-D06-DET-001 |
| Detection Name | Repeated Authentication Failures |
| Project | Project 05 — Microsoft Cloud SOC |
| Data Source | Microsoft Entra ID |
| Log Table | `SigninLogs` |
| Query Language | KQL |
| Severity | Medium — initial lab classification |
| Status | Query developed; synthetic logic validation passed |
| MITRE ATT&CK | T1110 — Brute Force |

## Objective

Identify repeated failed authentication attempts associated with the same user and source IP address within a 15-minute window.

## Detection Logic

The query groups failed sign-in events by:

- User principal name
- Source IP address
- 15-minute time window

A group is returned when it contains three or more failed sign-in records.

## Threshold

| Parameter | Value |
|---|---|
| Lookback period | 7 days |
| Time window | 15 minutes |
| Minimum failed attempts | 3 |
| Grouping | User + source IP + time window |

These values are initial lab settings and should be tuned against expected authentication behavior before production use.

## KQL Query

The executable query is maintained in:

`kql/authentication/day06-repeated-authentication-failures.kql`

## Validation Results

### Real Entra ID Telemetry

The seven-day baseline contained 38 sign-in records, including 3 failed records.

The detection query returned no groups meeting the configured threshold of at least three failures for the same user and source IP within 15 minutes.

### Synthetic Test

A KQL `datatable()` test generated four synthetic failed sign-in records for the same test user and IP within six minutes.

The detection logic returned one matching group containing all four records.

This validates the grouping and threshold logic against synthetic data. It does not establish that a real brute-force attack occurred or that a Microsoft Sentinel alert was generated.

## Investigation Guidance

When a matching group is returned:

1. Review the user principal name and source IP.
2. Inspect the failure result codes and descriptions.
3. Review the timestamps and frequency of attempts.
4. Check for successful sign-ins following the failures.
5. Examine related identity activity and application context.
6. Determine whether the activity is expected or suspicious.
7. Escalate according to the SOC incident-handling process if evidence supports further investigation.

Do not classify an event as a confirmed brute-force attack solely because the threshold was met.

## MITRE ATT&CK Mapping

**Technique:** T1110 — Brute Force

This mapping represents the behavior the detection is intended to identify. The observed lab activity has not been confirmed as a brute-force attack.

