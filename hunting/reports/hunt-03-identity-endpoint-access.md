# Hunt 03 — Identity Access to an Unusual Endpoint

## 1. Hypothesis
A potentially compromised identity may be accessing an endpoint in a way that differs from expected activity.

## 2. Data Sources
- Microsoft Sentinel: `SigninLogs`
- Microsoft Defender Advanced Hunting: `DeviceLogonEvents`, `DeviceProcessEvents`
- Entra ID identity: `ananthan@personalcybersecuritylab.onmicrosoft.com`
- Monitored endpoint: `p05-win10-ep`

## 3. Investigation
Previously collected Entra ID sign-in and endpoint telemetry were reviewed during Day 08 and Day 09.

The Entra ID account and local Windows account `soc-lab-user` represent separate identity contexts. A direct mapping between them has not been established.

## 4. Observation
The available sign-in telemetry contains activity for the Entra ID account. Endpoint telemetry is also available for the monitored Windows device.

However, the available evidence does not establish that the Entra ID sign-ins originated from, or directly correspond to, the local Windows account activity.

## 5. Conclusion
The hypothesis remains unconfirmed. The available evidence is insufficient to establish a compromised identity accessing an unusual endpoint.

## 6. Next Action
- Review existing sign-in details, source IPs, applications, and authentication outcomes.
- Review endpoint logon records and device identity information.
- Establish a reliable identity and device relationship before claiming direct correlation.

## 7. Evidence
Reference the relevant existing Day 08 and Day 09 screenshots. Do not duplicate screenshots unnecessarily.

## 8. Status
Inconclusive — direct identity-to-endpoint correlation has not been established.