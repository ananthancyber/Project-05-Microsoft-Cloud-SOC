# Day 06 — MITRE ATT&CK Mapping

## Detection Information

| Field | Value |
|---|---|
| Project | Project 05 — Microsoft Cloud SOC |
| Detection ID | P05-D06-DET-001 |
| Detection | Repeated Authentication Failures |
| Data source | Microsoft Entra ID |
| Table | `SigninLogs` |
| Detection threshold | At least 3 failures in 15 minutes for the same user and IP |

## Technique Mapping

| Field | Details |
|---|---|
| Framework | MITRE ATT&CK |
| Tactic | Credential Access |
| Technique ID | T1110 |
| Technique | Brute Force |
| Detection relevance | Repeated authentication failures can be consistent with brute-force behavior |

## Detection Logic

The detection groups failed authentication events by user principal name, source IP address, and 15-minute time window.

A group is returned when it contains at least three failed sign-in records.

## Validation Summary

- The seven-day Entra ID baseline contained 3 failed sign-in records.
- No group in the observed real telemetry met the configured detection threshold.
- A synthetic KQL test generated 4 test events within 15 minutes.
- The synthetic test returned one matching group.
- The synthetic test validates the query's threshold logic, not a real attack.

## Assessment

The detection is mapped to T1110 because it is designed to identify repeated authentication failures that may indicate brute-force behavior.

The observed lab telemetry did not establish a confirmed brute-force attack.

## Evidence References

- Daily documentation: `docs/Day06.md`
- Detection query: `kql/authentication/day06-repeated-authentication-failures.kql`
- Detection specification: `detections/day06-repeated-authentication-failures.md`
- Validation report: `validation/day06-repeated-authentication-failures-validation.md`