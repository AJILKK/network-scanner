VigilantScan - Network Scanning Tool
====================================

A powerful and user-friendly network scanning tool written in Python. VigilantScan allows you to perform various network scans, including ping scans, port scans, OS detection, vulnerability scans, and subnet scans. It also supports saving results in multiple formats (JSON, CSV, TXT).

---

Features
--------
- Ping Scan: Check if a host is alive.
- Port Scan: Scan for open ports and detect service versions.
- OS Detection: Detect the operating system of the target.
- Vulnerability Scan: Check for known vulnerabilities in detected services using the Vulners API.
- Subnet Scan: Scan an entire subnet for alive hosts.
- Multiple Output Formats: Save results in JSON, CSV, or TXT format.
- User-Friendly Menu: Easy-to-use interactive menu for selecting scan types.

---

Prerequisites
-------------
- Kali Linux: The tool is designed to run on Kali Linux.
- Python 3: Ensure Python 3 is installed.
- Required Libraries: Install the necessary Python libraries.

---

Installation
------------
1. Clone the Repository:

   git clone https://github.com/ajilkk/network-scanning-tool.git
   cd network-scanning-tool
   
2. Install Required Libraries:

   sudo apt update
   sudo apt install python3-pip
   pip install scapy python-nmap prettytable vulners

3. Set Up Vulners API:
   
  - Sign up for a free API key at https://vulners.com/.
  - Replace the placeholder in the `vulnerability_scan` function in the script with your Vulners API key:
    
    ```
    vulners_api = vulners.VulnersApi(api_key="YOUR_VULNERS_API_KEY")
    ```
---

Usage
-----

1. Run the Tool:

   - python3 vigilantscan.py
   
2. Interactive Menu:

   The tool will display a menu with the following options:
   
   === Network Scanning Tool ===

    1 - Scan a single IP or domain (Full Scan).
    2 - Ping Scan.
    3 - Port Scan.
    4. OS Detection.
    5 - Vulnerability Scan.
    6 - Subnet Scan.
    7 - Exit.
    Enter your choice (1-7):
   
4. Follow the Prompts:
   
  - Enter the target IP or domain when prompted.
  - Choose the desired scan type.
  - Select the output format (JSON, CSV, or TXT) when saving results.
---

Examples
--------

1. Full Scan:

   - Choose option 1 (Full Scan).
   - Enter the target (e.g., example.com or 192.168.1.1).
   - The tool will perform a ping scan, port scan, OS detection, and vulnerability scan.
   - Save the results in your preferred format.

2. Vulnerability Scan:
   
   - Choose option 5 (Vulnerability Scan).
   - Enter the target (e.g., example.com or 192.168.1.1).
   - The tool will scan for open ports and check for vulnerabilities using the Vulners API.
   - Save the results in your preferred format.

4. Subnet Scan:
   
   - Choose option 6 (Subnet Scan).
  - Enter the subnet (e.g., 192.168.1).
  - The tool will scan the subnet for alive hosts.
  - Save the results in your preferred format.

---

Output Formats
--------------

The tool supports saving results in the following formats:
- JSON: Structured data format.
- CSV: Comma-separated values format.
- TXT: Plain text format.

Example of saving results:

  Do you want to save the results? (yes/no): yes
  Enter the file name (without extension): result 
  Enter the file format (json/csv/txt): txt
  [+] Results saved to result.txt


---

Using the Vulners API
---------------------

The tool integrates with the Vulners API to check for known vulnerabilities in detected services. To use this feature:

1. Sign Up for Vulners:
   
   - Visit https://vulners.com/ and create an account.
   - Generate a free API key from your account dashboard.

3. Add Your API Key:
   
   - Open the script `advanced_network_scanner.py`.
   - Locate the `vulnerability_scan` function.
   - Replace `YOUR_VULNERS_API_KEY` with your actual Vulners API key:
     ```
     vulners_api = vulners.VulnersApi(api_key="YOUR_VULNERS_API_KEY")
     ```

4. Run the Tool:
   
   - The tool will now use the Vulners API to check for vulnerabilities during vulnerability scans.

---

Logging
-------
The tool logs all scan activities to a file named `network_scanner.log`. Check this file for debugging and tracking purposes.

---

Contributing
------------
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

---

License
-------
This project is licensed under the MIT License. See the LICENSE file for details.

---

Author
------
[AJIL K K](https://github.com/ajilkk)

---

Acknowledgments
---------------
- Inspired by tools like Nmap and Vulners.
- Built with Python libraries: scapy, python-nmap, prettytable, and vulners.
