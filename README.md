# Intrusion Prevention System (IPS)

A Python-based Intrusion Prevention System (IPS) that autonomously monitors network traffic for malicious IPs and scans files for malware using VirusTotal's API and iptables.

## Features
- **Network Monitoring**: Detects Nmap scans (SYN, XMAS) and blocks malicious IPs.
- **File Scanning**: Checks file hashes in a specified directory against VirusTotal to report malware presence.
- **IP Blocking**: Automatically blocks malicious IPs using iptables.
- **Logging**: Records all activities with unique case IDs in a log file.

## Prerequisites
- Python 3.6+
- Linux-based system (for iptables and Scapy packet sniffing)
- VirusTotal API key (sign up at [VirusTotal](https://www.virustotal.com/) to get one)
- Required Python packages:
  - `requests`
  - `scapy`
- Root privileges (for iptables and network sniffing)

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/flair19/intrusion-prevention.git
   cd intrusion-prevention
                                           
