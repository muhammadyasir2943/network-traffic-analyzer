\# Network Traffic Analyzer



A Python-based network traffic analyzer built with Scapy for capturing and analyzing basic IP packet metadata.



The project is designed as a hands-on cybersecurity learning project with a focus on network monitoring, packet analysis, and SOC/Blue Team fundamentals.



\## Overview



Network traffic analysis is an important part of cybersecurity monitoring and incident investigation.



This tool captures IP packets from the local system and extracts useful metadata such as:



\- Source IP address

\- Destination IP address

\- Protocol

\- Source port

\- Destination port

\- Timestamp



The analyzer also generates statistics and exports captured data for further investigation.



\## Features



\- Real-time packet capture

\- User-defined packet capture count

\- Packet numbering

\- Timestamp for each packet

\- IPv4 traffic analysis

\- TCP detection

\- UDP detection

\- ICMP detection

\- Protocol statistics

\- Top destination port statistics

\- Watchlist port detection

\- CSV report generation

\- PCAP capture generation

\- Wireshark-compatible packet capture

\- Capture summary



\## Technologies Used



\- Python 3

\- Scapy

\- CSV

\- Wireshark



\## Architecture



```text

&#x20;               Network Traffic

&#x20;                      |

&#x20;                      v

&#x20;               +--------------+

&#x20;               |    Scapy     |

&#x20;               | Packet Sniff |

&#x20;               +--------------+

&#x20;                      |

&#x20;                      v

&#x20;               +--------------+

&#x20;               | Packet       |

&#x20;               | Analysis     |

&#x20;               +--------------+

&#x20;                      |

&#x20;         +------------+-------------+

&#x20;         |            |             |

&#x20;         v            v             v

&#x20;     Protocol      Port Stats   Watchlist

&#x20;     Statistics      Analysis     Alerts

&#x20;         |            |             |

&#x20;         +------------+-------------+

&#x20;                      |

&#x20;                      v

&#x20;               +--------------+

&#x20;               |   Reporting  |

&#x20;               +--------------+

&#x20;                 /           \\

&#x20;                v             v

&#x20;             CSV Report     PCAP File

&#x20;                              |

&#x20;                              v

&#x20;                          Wireshark

```



\## Project Structure



```text

network-traffic-analyzer/

│

├── traffic\_analyzer.py

├── requirements.txt

├── README.md

└── .gitignore

```



\## Installation



\### 1. Clone the repository



```bash

git clone https://github.com/muhammadyasir2943/network-traffic-analyzer.git

```



\### 2. Enter the project directory



```bash

cd network-traffic-analyzer

```



\### 3. Install dependencies



```bash

python -m pip install -r requirements.txt

```



\## Usage



Run the analyzer:



```bash

python traffic\_analyzer.py

```



The program asks how many packets should be captured:



```text

Enter number of packets to capture \[default 20]: 20

```



The tool then captures and analyzes packets until the requested count is reached.



\## Example Output



```text

================================================================================

&#x20;                NETWORK TRAFFIC ANALYZER

================================================================================



Features:

&#x20; • Packet capture

&#x20; • Protocol statistics

&#x20; • Port statistics

&#x20; • Watchlist alerts

&#x20; • CSV reporting

&#x20; • PCAP export for Wireshark



Enter number of packets to capture \[default 20]: 20



\[+] Capturing 20 packets...

\[+] Generate some network traffic while capture is running.



NO.  TIME                 SOURCE IP        DESTINATION IP     PROTO   PORTS

\--------------------------------------------------------------------------------

\[001] 2026-09-16 18:14:52 | 10.26.218.44   -> 162.159.200.123 | UDP | 63196 -> 123

\[002] 2026-09-16 18:14:52 | 162.159.200.123 -> 10.26.218.44 | UDP | 123 -> 63196

\[003] 2026-09-16 18:14:52 | 10.26.218.44   -> 57.144.123.32  | TCP | 52284 -> 5222

```



\## Capture Summary



After packet capture, the tool generates statistics such as:



```text

CAPTURE SUMMARY



Total packets captured: 20



Protocol Statistics:

&#x20; TCP     : 18

&#x20; UDP     : 2



Top Destination Ports:

&#x20; Port 443   : 7 packets

&#x20; Port 7057  : 4 packets

&#x20; Port 5222  : 2 packets



Watchlist Events:

&#x20; No watchlist ports observed.

```



\## Watchlist Detection



The analyzer maintains a small watchlist of commonly monitored ports.



Examples include:



| Port | Service |

|------|---------|

| 21 | FTP |

| 23 | Telnet |

| 25 | SMTP |

| 139 | NetBIOS |

| 445 | SMB |

| 1433 | MSSQL |

| 3306 | MySQL |

| 3389 | RDP |

| 4444 | Common security-testing port |

| 5900 | VNC |



A watchlist match is \*\*not automatically considered malicious\*\*.



It simply identifies traffic that may deserve additional investigation.



\## CSV Reporting



The analyzer can export packet metadata to:



```text

traffic\_capture.csv

```



The report contains fields such as:



```text

packet\_number

timestamp

source\_ip

destination\_ip

protocol

source\_port

destination\_port

alert

```



This can be opened in Excel, LibreOffice Calc, or another data-analysis tool.



\## PCAP Export



The analyzer also creates:



```text

traffic\_capture.pcap

```



The PCAP file can be opened in \*\*Wireshark\*\* for deeper packet-level investigation.



Example workflow:



```text

Python Analyzer

&#x20;     |

&#x20;     v

traffic\_capture.pcap

&#x20;     |

&#x20;     v

Wireshark

&#x20;     |

&#x20;     v

Detailed Packet Analysis

```



\## Security Relevance



Network traffic analysis is relevant to several cybersecurity activities, including:



\- SOC monitoring

\- Incident response

\- Network troubleshooting

\- Threat detection

\- Traffic investigation

\- Security monitoring

\- Blue Team operations

\- Network reconnaissance analysis



A SOC analyst may inspect packet metadata to identify unusual connections, unexpected ports, communication patterns, or traffic that requires further investigation.



\## Learning Outcomes



Through this project, I practiced:



\- Python network programming

\- Packet capture

\- Scapy

\- TCP/IP concepts

\- TCP and UDP analysis

\- IP addressing

\- Port analysis

\- Network monitoring

\- Basic alerting logic

\- CSV reporting

\- PCAP generation

\- Wireshark workflow

\- Git and GitHub

\- Technical documentation



\## Limitations



This project currently focuses primarily on packet metadata.



It does not attempt to:



\- Perform deep packet inspection

\- Automatically classify traffic as malicious

\- Replace a professional IDS/IPS

\- Replace enterprise network monitoring platforms

\- Bypass network security controls



\## Future Improvements



Planned improvements include:



\- \[ ] Command-line arguments

\- \[ ] Protocol-specific filtering

\- \[ ] Network interface selection

\- \[ ] Traffic volume statistics

\- \[ ] Packet-size analysis

\- \[ ] Improved alert severity levels

\- \[ ] JSON export

\- \[ ] Visualization dashboard

\- \[ ] DNS traffic analysis

\- \[ ] HTTP metadata analysis

\- \[ ] Integration with threat-intelligence feeds

\- \[ ] Detection rules

\- \[ ] SIEM integration



\## Disclaimer



This project is intended for educational purposes and authorized network monitoring.



Only capture or analyze traffic on systems and networks where you have appropriate permission.



\## Author



\*\*Kuderu Mohammad Yasir\*\*



Cybersecurity | SOC | Networking | Python



GitHub:

https://github.com/muhammadyasir2943

