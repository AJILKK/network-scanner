import socket
import nmap
from scapy.all import ICMP, IP, sr1
from prettytable import PrettyTable
import vulners
import threading
import json
import csv
import logging
import time
import os

# Set up logging
logging.basicConfig(filename="network_scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to resolve domain to IP
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Resolved {domain} to IP: {ip}")
        logging.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except socket.error as e:
        print(f"[-] Could not resolve {domain}: {e}")
        logging.error(f"Could not resolve {domain}: {e}")
        return None

# Function to perform a ping scan
def ping_scan(ip):
    print(f"[*] Pinging {ip}...")
    logging.info(f"Pinging {ip}...")
    packet = IP(dst=ip)/ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        print(f"[+] {ip} is up!")
        logging.info(f"{ip} is up!")
        return True
    else:
        print(f"[-] {ip} is down or not responding.")
        logging.warning(f"{ip} is down or not responding.")
        return False

# Function to perform a port scan with advanced options
def port_scan(ip, ports="1-1024", arguments="-sV"):
    print(f"[*] Scanning {ip} for open ports with arguments: {arguments}...")
    logging.info(f"Scanning {ip} for open ports with arguments: {arguments}...")
    scanner = nmap.PortScanner()
    scanner.scan(ip, ports, arguments=arguments)  # Custom arguments

    # Create a table to display results
    table = PrettyTable()
    table.field_names = ["Port", "State", "Service", "Version"]

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']
                table.add_row([port, state, service, version])

    print(table)
    logging.info(f"Port scan results for {ip}:\n{table}")
    return scanner[ip]

# Function to detect OS
def os_detection(ip):
    print(f"[*] Detecting OS for {ip}...")
    logging.info(f"Detecting OS for {ip}...")
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments="-O")

    for host in scanner.all_hosts():
        if 'osclass' in scanner[host]:
            for osclass in scanner[host]['osclass']:
                print(f"[+] OS Detection: {osclass['osfamily']} ({osclass['osgen']})")
                logging.info(f"OS Detection: {osclass['osfamily']} ({osclass['osgen']})")
        else:
            print("[-] OS detection failed.")
            logging.warning("OS detection failed.")

# Function to check for vulnerabilities
def vulnerability_scan(ip, service, version):
    # Replace 'YOUR_API_KEY' with your actual Vulners API key
    vulners_api = vulners.VulnersApi(api_key="YQ7DYTXVT62MQZ83QYPKHK8ANTIS37ZQ02T6OAVXQBFJOMQW1MTD2H1U01G9252F")  # <-- Add your API key here
    if version:
        print(f"[*] Checking {service} {version} for vulnerabilities...")
        logging.info(f"Checking {service} {version} for vulnerabilities...")
        vulnerabilities = vulners_api.get_software_vulnerabilities(service, version)  # Corrected method name
        if vulnerabilities:
            print(f"[!] Vulnerabilities found for {service} {version}:")
            logging.warning(f"Vulnerabilities found for {service} {version}:")
            for vuln in vulnerabilities.get('vulnerabilities', [])[:5]:  # Show top 5 vulnerabilities
                print(f"    - {vuln['title']} (CVE: {vuln['cve']})")
                logging.warning(f"{vuln['title']} (CVE: {vuln['cve']})")
        else:
            print(f"[+] No vulnerabilities found for {service} {version}.")
            logging.info(f"No vulnerabilities found for {service} {version}.")
    else:
        print(f"[-] No version information available for {service}.")
        logging.warning(f"No version information available for {service}.")

# Function to scan a subnet for alive hosts
def subnet_scan(subnet):
    print(f"[*] Scanning subnet {subnet} for alive hosts...")
    logging.info(f"Scanning subnet {subnet} for alive hosts...")
    alive_hosts = []
    threads = []

    def scan_host(ip):
        if ping_scan(ip):
            alive_hosts.append(ip)

    # Ensure the subnet is in the correct format (e.g., "192.168.1")
    if subnet.count('.') != 2:
        print("[-] Invalid subnet format. Please use the format 'X.X.X' (e.g., 192.168.1).")
        logging.error(f"Invalid subnet format: {subnet}")
        return alive_hosts

    for i in range(1, 255):
        ip = f"{subnet}.{i}"  # Correctly format the IP address
        thread = threading.Thread(target=scan_host, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(f"[+] Alive hosts in {subnet}: {alive_hosts}")
    logging.info(f"Alive hosts in {subnet}: {alive_hosts}")
    return alive_hosts

# Function to save results to a file
def save_results(results, filename="scan_results", format="txt"):
    if format == "json":
        with open(f"{filename}.json", "w") as file:
            json.dump(results, file, indent=4)
        print(f"[+] Results saved to {filename}.json")
        logging.info(f"Results saved to {filename}.json")
    elif format == "csv":
        with open(f"{filename}.csv", "w", newline="") as file:
            writer = csv.writer(file)
            if isinstance(results, dict) and "alive_hosts" in results:
                # Handle subnet scan results
                writer.writerow(["Alive Hosts"])
                for host in results["alive_hosts"]:
                    writer.writerow([host])
            else:
                # Handle single IP scan results
                writer.writerow(["IP", "Port", "State", "Service", "Version"])
                for ip, data in results.items():
                    for proto in data.all_protocols():
                        ports = data[proto].keys()
                        for port in ports:
                            state = data[proto][port]['state']
                            service = data[proto][port]['name']
                            version = data[proto][port]['version']
                            writer.writerow([ip, port, state, service, version])
        print(f"[+] Results saved to {filename}.csv")
        logging.info(f"Results saved to {filename}.csv")
    elif format == "txt":
        with open(f"{filename}.txt", "w") as file:
            if isinstance(results, dict) and "alive_hosts" in results:
                # Handle subnet scan results
                file.write("Alive Hosts:\n")
                for host in results["alive_hosts"]:
                    file.write(f"{host}\n")
            else:
                # Handle single IP scan results
                for ip, data in results.items():
                    file.write(f"IP: {ip}\n")
                    for proto in data.all_protocols():
                        ports = data[proto].keys()
                        for port in ports:
                            state = data[proto][port]['state']
                            service = data[proto][port]['name']
                            version = data[proto][port]['version']
                            file.write(f"Port: {port}, State: {state}, Service: {service}, Version: {version}\n")
        print(f"[+] Results saved to {filename}.txt")
        logging.info(f"Results saved to {filename}.txt")
    else:
        print("[-] Invalid format. Results not saved.")
        logging.error("Invalid format. Results not saved.")

# Function to display the home menu
def home_menu():
    print("\n-------- VigilantScan -------")
    print("=== Network Scanning Tool ===\n")
    print("1. Scan a single IP or domain (Full Scan)")
    print("2. Ping Scan")
    print("3. Port Scan")
    print("4. OS Detection")
    print("5. Vulnerability Scan")
    print("6. Subnet Scan")
    print("7. Firewall Evasion Scan")
    print("8. Exit")
    choice = input("Enter your choice (1-8): ").strip()
    return choice

# Main function
def main():
    results = {}

    while True:
        choice = home_menu()

        if choice == "1":  # Full Scan
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            if ping_scan(ip):
                port_results = port_scan(ip, arguments="-sV -O")  # Service and OS detection
                results[ip] = port_results

                os_detection(ip)

                for proto in port_results.all_protocols():
                    ports = port_results[proto].keys()
                    for port in ports:
                        service = port_results[proto][port]['name']
                        version = port_results[proto][port]['version']
                        vulnerability_scan(ip, service, version)

                save_option = input("Do you want to save the results? (yes/no): ").strip().lower()
                if save_option == "yes":
                    filename = input("Enter the file name (without extension): ").strip()
                    format = input("Enter the file format (json/csv/txt): ").strip().lower()
                    save_results(results, filename=filename, format=format)

        elif choice == "2":  # Ping Scan
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            ping_scan(ip)

        elif choice == "3":  # Port Scan
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            arguments = input("Enter additional Nmap arguments (e.g., -sS -sV): ").strip()
            port_results = port_scan(ip, arguments=arguments)

            save_option = input("Do you want to save the results? (yes/no): ").strip().lower()
            if save_option == "yes":
                filename = input("Enter the file name (without extension): ").strip()
                format = input("Enter the file format (json/csv/txt): ").strip().lower()
                save_results({ip: port_results}, filename=filename, format=format)

        elif choice == "4":  # OS Detection
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            os_detection(ip)

        elif choice == "5":  # Vulnerability Scan
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            port_results = port_scan(ip)
            for proto in port_results.all_protocols():
                ports = port_results[proto].keys()
                for port in ports:
                    service = port_results[proto][port]['name']
                    version = port_results[proto][port]['version']
                    vulnerability_scan(ip, service, version)

        elif choice == "6":  # Subnet Scan
            subnet = input("Enter the subnet (e.g., 192.168.1): ").strip()
            if subnet.count('.') != 2:
                print("[-] Invalid subnet format. Please use the format 'X.X.X' (e.g., 192.168.1).")
                logging.error(f"Invalid subnet format: {subnet}")
                continue

            alive_hosts = subnet_scan(subnet)
            results["alive_hosts"] = alive_hosts

            save_option = input("Do you want to save the results? (yes/no): ").strip().lower()
            if save_option == "yes":
                filename = input("Enter the file name (without extension): ").strip()
                format = input("Enter the file format (json/csv/txt): ").strip().lower()
                save_results(results, filename=filename, format=format)

        elif choice == "7":  # Firewall Evasion Scan
            target = input("Enter the target IP or domain: ").strip()
            if not target.replace('.', '').isdigit():
                ip = resolve_domain(target)
                if not ip:
                    continue
            else:
                ip = target

            print("\n=== Firewall Evasion Techniques ===")
            print("1. Fragmentation (-f)")
            print("2. Decoy Scanning (-D)")
            print("3. Idle Scanning (-sI)")
            print("4. Source Port Manipulation (--source-port)")
            evasion_choice = input("Enter your choice (1-4): ").strip()

            if evasion_choice == "1":
                arguments = "-f"  # Fragmentation
            elif evasion_choice == "2":
                decoys = input("Enter decoy IPs (comma-separated): ").strip()
                arguments = f"-D {decoys}"  # Decoy scanning
            elif evasion_choice == "3":
                zombie_ip = input("Enter zombie IP: ").strip()
                arguments = f"-sI {zombie_ip}"  # Idle scanning
            elif evasion_choice == "4":
                source_port = input("Enter source port: ").strip()
                arguments = f"--source-port {source_port}"  # Source port manipulation
            else:
                print("[-] Invalid choice. Using default scan.")
                arguments = ""

            port_results = port_scan(ip, arguments=arguments)

            save_option = input("Do you want to save the results? (yes/no): ").strip().lower()
            if save_option == "yes":
                filename = input("Enter the file name (without extension): ").strip()
                format = input("Enter the file format (json/csv/txt): ").strip().lower()
                save_results({ip: port_results}, filename=filename, format=format)

        elif choice == "8":  # Exit
            print("[-] Exiting the tool. Goodbye!")
            logging.info("Exiting the tool.")
            break

        else:
            print("[-] Invalid choice. Please try again.")
            logging.warning("Invalid choice entered.")

if __name__ == "__main__":
    main()
