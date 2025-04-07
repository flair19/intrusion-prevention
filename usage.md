# Usage Examples for ips.py

This file provides examples of how to use `ips.py` with sample commands and expected outputs.

## Example 1: Basic Monitoring with Threats
**Command:**
```bash
sudo python3 ips.py



Expected Output
Starting continuous monitoring...
[NETWORK] Sniffing network traffic for 60 seconds...
[NETWORK] Possible Nmap scan detected from 192.168.1.100
[BLOCK] IP 192.168.1.100 has been blocked
[FILE SCAN] Scanning directory: /home/mrhacker
[FILE SCAN] File /home/mrhacker/test.exe (hash: abc123456789...) - Malicious: True
[FILE SCAN] File /home/mrhacker/doc.txt (hash: def456789123...) - Malicious: False


Incase no threats are detected 
sudo python3 ips.py

Expected Output
Starting continuous monitoring...
[NETWORK] Sniffing network traffic for 60 seconds...
[FILE SCAN] Scanning directory: /home/mrhacker
[FILE SCAN] File /home/mrhacker/note.txt (hash: ghi789123456...) - Malicious: False
[FILE SCAN] File /home/mrhacker/script.py (hash: jkl012345678...) - Malicious: False


Error Handling
Description: Shows output when an error occurs (e.g., file not found on VirusTotal).

Expected Output:

Starting continuous monitoring...
[NETWORK] Sniffing network traffic for 60 seconds...
[FILE SCAN] Scanning directory: /home/mrhacker
[ERROR] Error checking file /home/mrhacker/missing.bin: HTTP 404
[FILE SCAN] File /home/mrhacker/doc.txt (hash: def456789123...) - Malicious: False
                                                         
