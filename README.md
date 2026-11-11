\# SOC Security Monitoring and Threat Detection Using Splunk



\## Project Overview



This project demonstrates a beginner-level Security Operations Center (SOC) monitoring workflow using Splunk Enterprise.



The project uses a simulated Windows authentication log dataset to identify suspicious login activity, investigate authentication events, visualize security indicators, and validate a scheduled security alert.



\*\*Project Type:\*\* Cybersecurity / SOC Analyst L1 Lab  

\*\*Platform:\*\* Windows 11 with Ubuntu 24.04 on WSL2  

\*\*SIEM Tool:\*\* Splunk Enterprise 10.6.1.1  

\*\*Log Source:\*\* Simulated Windows Security Events (CSV)



\## Objectives



\- Ingest simulated security logs into Splunk.

\- Analyze successful and failed authentication events.

\- Identify IP addresses generating repeated failed logins.

\- Correlate failed and successful authentication events.

\- Build a SOC monitoring dashboard.

\- Configure and validate a scheduled detection alert.

\- Document a simulated security incident.



\## Tools and Technologies



\- Splunk Enterprise

\- Search Processing Language (SPL)

\- Ubuntu Linux (WSL2)

\- Windows 11

\- CSV log datasets



\## Security Events Monitored



| Event ID | Description |

|---|---|

| 4624 | Successful login |

| 4625 | Failed login |

| 4740 | Account lockout |



\## Detection Scenario



The simulated dataset contains five failed login attempts targeting the `admin` account from source IP `192.168.1.50`, followed by one successful login from the same account and IP address.



The pattern was investigated as possible brute-force activity followed by successful authentication.



The available evidence does not confirm unauthorized access or account compromise.



\## Detection Query



```spl

index=soc\_lab (EventCode=4624 OR EventCode=4625)

| stats count(eval(EventCode=4625)) as Failed\_Logins

&#x20;       count(eval(EventCode=4624)) as Successful\_Logins

&#x20;       by Account\_Name Source\_IP

| where Failed\_Logins>=5 AND Successful\_Logins>=1

| eval Detection="Possible Brute Force Followed by Success"

| table Account\_Name Source\_IP Failed\_Logins Successful\_Logins Detection

```



This lab detection identifies accounts and source IPs meeting the configured failure and success thresholds. Event ordering was verified separately using a timeline search.



\## SOC Monitoring Dashboard



A Splunk dashboard was created to display:



1\. Total failed login attempts

2\. Total successful logins

3\. Suspicious source IP addresses

4\. Total account lockouts



!\[SOC Monitoring Dashboard](Screenshots/Dashboard.png)



\## Alert Validation



A scheduled Splunk alert named \*\*SOC - Possible Brute Force Login\*\* was configured and enabled.



The alert successfully triggered during testing and returned one detection result involving:



\- Account: `admin`

\- Source IP: `192.168.1.50`

\- Failed logins: 5

\- Successful logins: 1



!\[Alert Detection Results](Screenshots/alert\_detection\_results.png)



\## Incident Investigation



A simulated incident report, \*\*INC-001\*\*, documents the suspicious authentication timeline, investigation findings, severity assessment, and recommended response actions.



See \[Incident Investigation Report](Incident\_Report\_INC001.txt).



\## Repository Structure



```text

SOC\_Security\_Monitoring/

├── Screenshots/

│   ├── Dashboard.png

│   └── alert\_detection\_results.png

├── logs/

│   └── windows\_security.csv

├── spl\_queries/

│   └── detection\_queries.spl

├── Incident\_Report\_INC001.txt

└── README.md

```



\## Skills Demonstrated



\- SIEM fundamentals

\- Security log ingestion and analysis

\- Splunk SPL queries

\- Authentication event investigation

\- Suspicious login detection

\- Security dashboard development

\- Scheduled alert configuration and validation

\- SOC incident documentation



\## Limitations



This project uses simulated authentication logs rather than live Windows Event Log collection. The alert was validated using historical lab data and an All time search window. It is a demonstration of a SOC detection workflow, not a production-ready detection rule.



\## Conclusion



This project demonstrates a practical introductory SOC monitoring workflow, from log ingestion and threat detection to alert validation and incident reporting.



It provides hands-on experience with Splunk Enterprise and foundational SOC Analyst L1 investigation tasks.

