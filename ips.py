import requests
import hashlib
import os
import socket
import scapy.all as scapy 
import logging
import random
import string
import subprocess
import time
import json


class IntrusionPreventionSystem:
    def __init__(self, api_key, log_file, base_dir):
        self.api_key = api_key  # Virus Total API key
        self.log_file = log_file  # Path to log file
        self.base_dir = base_dir  # Directory to scan for files
        self.blocked_ips = set()  # Track blocked IPs to avoid duplication

        # Set up logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

    def generate_case_id(self):
        # Generate a unique 4-character long case id
        characters = string.ascii_letters + string.digits
        case_id = ''.join(random.choice(characters) for _ in range(4))
        return case_id
    
    def check_ip_virustotal(self, ip_address):
        # Query VirusTotal to check if IP is flagged as malicious
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.api_key}
        try: 
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) > 0
        except requests.RequestException as e:
            self.log_activity(self.generate_case_id(), f"Error checking IP {ip_address}: {e}")
            return False

    def block_ip(self, ip_address, case_id):
        # Block an IP address if it is flagged as malicious
        if ip_address not in self.blocked_ips:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
                self.blocked_ips.add(ip_address)
                self.log_activity(case_id, f"Blocked IP: {ip_address}")
                print(f"[BLOCK] IP {ip_address} has been blocked")
            except subprocess.CalledProcessError as e:
                self.log_activity(case_id, f"Failed to block IP {ip_address}: {e}")
                print(f"[ERROR] Failed to block IP {ip_address}: {e}")

    def generate_file_hash(self, file_path):
        # Generate a SHA256 hash value for a given file
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest() 
           
    def check_file_virustotal(self, file_path, case_id):
        # Check if the file hash is flagged as malicious on VirusTotal
        file_hash = self.generate_file_hash(file_path)
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            is_malicious = stats.get("malicious", 0) > 0
            self.log_activity(case_id, f"File {file_path} (hash: {file_hash}) - Malicious: {is_malicious}")
            print(f"[FILE SCAN] File {file_path} (hash: {file_hash}) - Malicious: {is_malicious}")
            return is_malicious
        except requests.RequestException as e:
            self.log_activity(case_id, f"Error checking file {file_path}: {e}")
            print(f"[ERROR] Error checking file {file_path}: {e}")
            return False
        
    def monitor_files(self):
        # Monitor the specified directory and check files against VirusTotal
        print(f"[FILE SCAN] Scanning directory: {self.base_dir}")
        for root, _, files in os.walk(self.base_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                case_id = self.generate_case_id()
                self.check_file_virustotal(file_path, case_id)
                time.sleep(1)  # Rate limit to avoid overwhelming VirusTotal
                
    def detect_nmap_scans(self):
        # Analyze network traffic to detect Nmap scans
        def packet_callback(packet):
            if packet.haslayer(scapy.TCP):
                flags = packet[scapy.TCP].flags
                # Detect SYN scan (S flag only) or XMAS scan (FIN, PSH, URG)
                if flags == "S" or flags == "FPU":
                    case_id = self.generate_case_id()
                    src_ip = packet[scapy.IP].src
                    self.log_activity(case_id, f"Possible Nmap scan detected from {src_ip}")
                    print(f"[NETWORK] Possible Nmap scan detected from {src_ip}")
                    if self.check_ip_virustotal(src_ip):
                        self.block_ip(src_ip, case_id)

        # Sniff packets for 60 seconds
        print("[NETWORK] Sniffing network traffic for 60 seconds...")
        scapy.sniff(timeout=60, prn=packet_callback) 

    def log_activity(self, case_id, message):
        # Log an activity with a case id and message
        self.logger.info(f"[Case: {case_id}] {message}")
    
    def test_malicious_ip(self, test_ip="185.234.247.222"):
        # Test function to check a known malicious IP
        case_id = self.generate_case_id()
        self.log_activity(case_id, f"TESTING: Checking IP: {test_ip}")
        print(f"[TEST] Starting test with IP: {test_ip}")
        is_malicious = self.check_ip_virustotal(test_ip)
        if is_malicious:
            self.log_activity(case_id, f"TESTING: IP {test_ip} correctly identified as malicious")
            print(f"[TEST] Success! IP {test_ip} was detected as malicious")
            self.block_ip(test_ip, case_id)
        else:
            self.log_activity(case_id, f"TESTING: Warning - IP {test_ip} not detected as malicious")
            print(f"[TEST] Warning: IP {test_ip} was not detected as malicious by VirusTotal")
        return is_malicious

    def run(self):
        # Main loop to run the IPS continuously
        print("Starting continuous monitoring...")
        while True:
            self.detect_nmap_scans()  # Check for malicious IPs in network traffic
            self.monitor_files()      # Check for malware in files
            time.sleep(5)             # Pause between cycles to avoid overwhelming resources


# Example usage 
if __name__ == "__main__":
    import sys
    
    # Create the IPS instance
    # Replace "YOUR_VIRUSTOTAL_API_KEY" with your actual VirusTotal API key
    ips = IntrusionPreventionSystem(
        api_key="YOUR_VIRUSTOTAL_API_KEY",  # Get your key from https://www.virustotal.com/
        log_file="ips_log.txt",
        base_dir="/home/mrhacker"
    )
    
    # Run the script in autonomous monitoring mode
    ips.run()
