# Day 10 — IOC Enrichment Report

## 1. Objective

Investigate selected external IP addresses observed in Microsoft Defender
network telemetry. Enrich each indicator using VirusTotal and assess
whether the available evidence supports a malicious, benign, or
inconclusive classification.

## 2. Investigation Environment

- Project: Project 05 — Microsoft Cloud SOC, EDR & Threat Hunting Lab
- Endpoint: `p05-win10-ep`
- Primary data source: Microsoft Defender Advanced Hunting
- Network telemetry table: `DeviceNetworkEvents`
- External enrichment: VirusTotal
- Investigation period: Last 7 days for network events
- IOC enrichment: VirusTotal reports viewed during this investigation

## 3. Methodology

1. Reviewed endpoint network-event telemetry.
2. Summarized network activity by action type.
3. Identified remote IP addresses associated with failed connections.
4. Reviewed individual events, destination ports, and initiating processes.
5. Checked selected public IP addresses in VirusTotal.
6. Compared the available reputation and network context with endpoint evidence.
7. Assigned a confidence-based assessment without treating reputation alone
   as proof of maliciousness.

## 4. IOC Enrichment Findings

### IOC 1 — 93.123.17.253

**Endpoint observations**

- Failed connection events: 2
- Destination port: 80
- Initiating process: `svchost.exe`

**VirusTotal observations**

- Detection ratio: 0/92
- Network range: `93.123.17.0/24`
- ASN: `AS199524`
- Network owner: G-Core Labs S.A.
- Country shown: Netherlands (NL)
- Last analysis shown: 11 hours ago

**Assessment**

No security vendor shown in the captured report flagged the IP as malicious.
The endpoint recorded two failed connections to this address.

The available evidence does not establish why the connections failed or
whether the destination was expected for the initiating service.

**Classification:** Inconclusive

**Confidence:** Low confidence in any maliciousness determination.

**Next action:** Investigate the initiating Windows service and review
additional network context if relevant telemetry becomes available.

**Evidence**

![VirusTotal report for 93.123.17.253](../../screenshots/Day10/Day10-07-VirusTotal-93-123-17-253.png)

### IOC 2 — 92.223.76.254

**Endpoint observations**

- Failed connection events: 1
- Destination port: 80
- Initiating process: `svchost.exe`

**VirusTotal observations**

- Detection ratio: 0/92
- Network range: `92.223.76.0/23`
- ASN: `AS199524`
- Network owner: G-Core Labs S.A.
- Country shown: Hong Kong (HK)
- Last analysis shown: 29 minutes ago
- Related files communicating with this IP: 6

**Assessment**

No security vendor shown in the captured report flagged the IP as malicious.
VirusTotal listed six related files communicating with the address, but
the displayed count does not establish that those files were malicious.

The endpoint recorded one failed connection. The available evidence does not
establish the purpose of the connection or why it failed.

**Classification:** Inconclusive

**Confidence:** Low confidence in any maliciousness determination.

**Next action:** Review related infrastructure and endpoint context if
additional evidence becomes available.

**Evidence**

![VirusTotal report for 92.223.76.254](../../screenshots/Day10/Day10-08-VirusTotal-92-223-76-254.png)

### IOC 3 — 172.167.181.234

**Endpoint observations**

- Failed connection events: 1
- Destination port: 443
- Initiating process: `searchapp.exe`

**VirusTotal observations**

- Detection ratio: 0/92
- Network range: `172.128.0.0/10`
- ASN: `AS8075`
- Network owner: Microsoft Corporation
- Country shown: United Kingdom (GB)
- Last analysis shown: 3 days ago
- Additional label displayed: `self-signed`

**Assessment**

No security vendor shown in the captured report flagged the IP as malicious.
The address is associated with a network registered to Microsoft.

Network ownership alone does not prove that a specific connection was
benign. The endpoint recorded one failed connection, and the available
evidence does not establish why it failed.

The meaning and relevance of the `self-signed` label were not independently
verified during this investigation.

**Classification:** Inconclusive

**Confidence:** Low confidence in any maliciousness determination.

**Next action:** Verify whether the destination is expected for the
application and investigate further if corroborating evidence appears.

**Evidence**

![VirusTotal report for 172.167.181.234](../../screenshots/Day10/Day10-09-VirusTotal-172-167-181-234.png)

## 5. Summary of Findings

| Indicator | Observed events | Destination port | Initiating process | VirusTotal | Assessment |
|---|---:|---:|---|---|---|
| 93.123.17.253 | 2 failed connections | 80 | `svchost.exe` | 0/92 | Inconclusive |
| 92.223.76.254 | 1 failed connection | 80 | `svchost.exe` | 0/92 | Inconclusive |
| 172.167.181.234 | 1 failed connection | 443 | `searchapp.exe` | 0/92 | Inconclusive |

The four selected events do not establish successful communication with
malicious infrastructure.

## 6. Confidence Assessment

The current evidence is insufficient to classify any of the three IP
addresses as malicious or definitively benign.

The VirusTotal reports showed zero detections among the 92 vendors displayed.
This is one source of reputation context, not proof that an indicator is safe.

The observed network failures are investigative leads. They do not, by
themselves, establish malicious intent.

Confidence in a maliciousness determination is therefore low.

## 7. Limitations

- The investigation covered selected endpoint telemetry and public IP reports.
- No direct relationship between these IP addresses and a confirmed attack
  was established.
- No successful malicious connection was established from the reviewed events.
- The VirusTotal results reflect the reports at the time they were viewed.
- Additional DNS, process ancestry, service, proxy, firewall, or network
  evidence could change the assessment.
- Microsoft Sentinel's `ThreatIntelIndicators` query returned zero records
  in the queried workspace and time range. This does not prove that no
  threat intelligence exists elsewhere.

## 8. Conclusion

This investigation demonstrated how to combine endpoint network telemetry
with external IOC enrichment.

Three external IP addresses associated with failed connection events were
reviewed in VirusTotal. None was flagged by the 92 security vendors shown
in the captured reports.

Based on the evidence collected, all three indicators remain inconclusive.
No confirmed malicious activity was established.

A SOC analyst should continue investigating when additional contextual
evidence warrants it, rather than blocking an address solely because it
appears in a network-event record.