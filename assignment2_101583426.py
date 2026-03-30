"""
Author: Travis Eweka
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# A dictionary mapping common port numbers to their standard network service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = "127.0.0.1" # Default safe state
        self.target = target # Calls the setter for validation

    # Q3: What is the benefit of using @property and @target.setter?
    # Properties allow us to encapsulate the private __target variable and enforce validation rules whenever the value is modified.
    # This ensures external code cannot bypass our rules to set the target to an empty string, while still keeping attribute access syntax simple.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits the target IP management logic directly from NetworkTool.
# For example, it reuses the @target.setter validation to ensure the IP address is not an empty string upon initialization without needing to rewrite that logic.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        try:
            super().__del__()
        except AttributeError:
            pass

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, if the socket encounters a network issue (like an unreachable host), an unhandled exception would be raised.
        # This would immediately crash the thread or the entire program instead of allowing it to print an error and continue scanning other ports gracefully.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
                
            service_name = common_ports.get(port, "Unknown")
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows us to attempt connections to multiple ports simultaneously, drastically speeding up the process.
    # If we scanned 1024 ports sequentially with a 1-second timeout, it would take up to 1024 seconds (over 17 minutes) if most ports were closed or filtered.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        
        scan_date = str(datetime.datetime.now())
        for result in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)", 
                           (target, result[0], result[1], result[2], scan_date))
            
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

if __name__ == "__main__":
    target_ip = input("Enter target IP (default 127.0.0.1): ").strip()
    if not target_ip:
        target_ip = "127.0.0.1"
        
    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
        
        if not (1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)
            
            open_ports = scanner.get_open_ports()
            print(f"--- Scan Results for {target_ip} ---")
            for port_info in open_ports:
                print(f"Port {port_info[0]}: {port_info[1]} ({port_info[2]})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")
            
            save_results(target_ip, open_ports)
            
            view_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if view_history in ["yes", "y"]:
                load_past_scans()
                
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal - Cleartext Protocol Alerter
# This feature would scan the final list of open ports to identify outdated, unencrypted protocols like FTP (21) or Telnet (23) that pose a severe security risk. 
# It would use a list comprehension to quickly filter the scan_results list, returning only the tuples where the port number matches these known cleartext services so the tool can print a targeted security warning.
# Diagram: See diagram_101583426.png in the repository root