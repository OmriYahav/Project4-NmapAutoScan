import nmap
from time import time_ns
from colorama import Fore, Back, Style
import re

# Wellcome banner
print(Fore.LIGHTMAGENTA_EX + "Wellcome to Omriyx Automate  Nmap Scanner")

# Regular expression patterns for IP addresses and port numbers
ipv4_pattern = "^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
port_pattern = "^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$"

# initialize the port scanner
nmScan = nmap.PortScanner()

def Port_Scanner():
    start_time = time_ns()
    nmScan.scan(ip1, port1)
    # create a list to store the results
    results = []
    # run a loop to extract the port scan results and store them in the list
    for host in nmScan.all_hosts():
        ip = nmScan[host]['addresses']['ipv4']
        state = nmScan[host].state()
        hostname = nmScan[host].hostname()
        open_ports = []  # initialize open_ports here, for each host
        services = [] # initialize services here, for each host
        os = 'Unknown'

        if 'osmatch' in nmScan[host]:
            os = nmScan[host]['osmatch'][0]['osclass'][0]['osfamily']
        for proto in nmScan[host].all_protocols():
            protocol = proto
            for port in nmScan[host][proto]:
                port_num = port
                port_state = nmScan[host][proto][port]['state']
                if port_state == 'open':
                    open_ports.append(port_num)
                    service = nmScan[host][proto][port]['name']
                    if service not in services:
                        services.append(service)

            result = {
                'hostname': hostname,
                'ip': ip,
                'state': state,
                'protocol': protocol,
                'open_ports': open_ports,
                'services': services,
                'os': os
            }

            results.append(result)
            print(Fore.LIGHTYELLOW_EX + 'Elapsed Time Since Port Scanner Start :', end=" ")
            print(Fore.LIGHTRED_EX + f'{(time_ns() - start_time) // (1000000000)} seconds')

            if len(result["open_ports"]) == 0:
                print(Fore.LIGHTWHITE_EX + "NO OPEN PORTS FOUND!")
            else:
                print(Fore.LIGHTWHITE_EX + "OPEN PORTS FOUND!")

    # print the results
    print(Fore.LIGHTYELLOW_EX + "Scan Results:\n")
    for result in results:
        print(Fore.LIGHTGREEN_EX + "IP Address: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["ip"]}')

        print(Fore.LIGHTGREEN_EX + "Hostname: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["hostname"]}')

        print(Fore.LIGHTGREEN_EX + "State: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["state"]}')

        print(Fore.LIGHTGREEN_EX + "Operating System: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["os"]}')

        print(Fore.LIGHTGREEN_EX + "Open Ports: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["open_ports"]}')

        print(Fore.LIGHTGREEN_EX + "Services: ", end="")
        print(Fore.LIGHTRED_EX + f'{result["services"]}\n')


def Comprehensive_scan():
    start_time = time_ns()
    nmScan = nmap.PortScanner()
    nmScan.scan(ip1, '1-1024', '-v -sS -sV -sC -A -O')
    all_hosts = nmScan.all_hosts()

    print(f"\n{Fore.LIGHTYELLOW_EX}---------------------------------------------")
    print(f"{Fore.LIGHTYELLOW_EX}Comprehensive scan report for {ip1}")
    print(f"{Fore.LIGHTYELLOW_EX}---------------------------------------------")

    elapsed_time = (time_ns() - start_time) // (1000000000)
    print(f"\n{Fore.LIGHTYELLOW_EX}Scan completed in {elapsed_time} seconds")

    for host in all_hosts:
        print(f"\n{Fore.LIGHTCYAN_EX}Host: {host}")
        print(f"State: {nmScan[host].state()}")
        print(f"OS Detection: {nmScan[host]['osmatch'][0]['name']}")

        tcp_ports = []
        udp_ports = []
        for protocol in nmScan[host].all_protocols():
            ports = nmScan[host][protocol].keys()
            for port in ports:
                if protocol == 'tcp':
                    tcp_ports.append(port)
                else:
                    udp_ports.append(port)

        if tcp_ports:
            print(f"\n{Fore.LIGHTGREEN_EX}TCP Ports:")
            print(f"{Fore.LIGHTGREEN_EX}----------")
            for port in sorted(tcp_ports):
                service = nmScan[host]['tcp'][port]['name']
                version = nmScan[host]['tcp'][port]['version']
                product = nmScan[host]['tcp'][port]['product']
                print(f"{port}/{protocol}  {service} {version} ({product})")

        if udp_ports:
            print(f"\n{Fore.LIGHTGREEN_EX}UDP Ports:")
            print(f"{Fore.LIGHTGREEN_EX}----------")
            for port in sorted(udp_ports):
                service = nmScan[host]['udp'][port]['name']
                version = nmScan[host]['udp'][port]['version']
                product = nmScan[host]['udp'][port]['product']
                print(f"{port}/{protocol}  {service} {version} ({product})")

# Loop for continuously prompting user for scanning option
while True:
    # Prompt user to select scanning option
    userInput = input(Fore.LIGHTBLUE_EX +"1.Comprehensive Scan\n2.Single IP Scan with custom ports\n3.Multiple IP Scan with custom ports\n")
    print(Fore.LIGHTYELLOW_EX + "You have selected option: ", userInput)

    # Check the selected option
    if userInput == '1':
        while True:
            # Loop for continuously prompting user for valid IP address
            # Prompt user to enter single IP address
            SingleIP = input(Fore.LIGHTGREEN_EX + "Enter a Single IP Address: ")
            # Check if the IP address is valid
            if re.match(ipv4_pattern, SingleIP):
                print("Valid IPv4 address!")
                print("Processing..")
                # Store the validated IP address
                ip1 = SingleIP
                # Perform comprehensive scan on the specified IP
                Comprehensive_scan()
                # Exit the inner loop
                break  # Add break here to exit the loop
            else:
                print(Fore.LIGHTRED_EX + "Invalid IPv4 address.")
        break  # Add break here to exit the outer loop


    if userInput == '2':
        # Loop for continuously prompting user for valid IP address

        while True:
            # Prompt user to enter single IP address

            SingleIP = input(Fore.LIGHTGREEN_EX + "Enter a Single IP Address: ")
            # Check if the IP address is valid

            if re.match(ipv4_pattern, SingleIP):
                print("Valid IPv4 address!")
                # Store the validated IP address

                ip1 = SingleIP
                break  # Add break here to exit the loop
            else:
                print(Fore.LIGHTRED_EX + "Invalid IPv4 address.")

        # Loop for continuously prompting user for valid port range
        while True:
            # Prompt user to enter port range

            StartPort = input('Enter Start Port : ')
            EndPort = input('Enter End Port : ')
            # Check if the port numbers are valid

            if re.match(port_pattern, StartPort) and re.match(port_pattern, EndPort):
                # Store the validated port range

                port1 = str(StartPort + "-" + EndPort)
                print(Fore.LIGHTYELLOW_EX + "Scanning: ", end="")
                print(Fore.LIGHTBLUE_EX + f'{ip1} ', end="")
                print(Fore.LIGHTYELLOW_EX + ", Port Range: ", end="")
                print(Fore.LIGHTBLUE_EX + f'{port1}')
                print("Processing..")
                # Perform port scan on the specified IP and port range

                Port_Scanner()
                break  # Add break here to exit the loop
            else:
                print(Fore.LIGHTRED_EX + "Invalid Port , ports are only between 1-65535")
        break  # Add break here to exit the outer loop

    elif userInput == '3':
        # Loop for continuously prompting user for valid IP address

        while True:
            StartIP = input(Fore.LIGHTGREEN_EX + "Enter Start IP : ")
            EndIP = input(Fore.LIGHTGREEN_EX + "Enter End IP : ")
            # Check if the IP addresses are valid
            if re.match(ipv4_pattern, StartIP) and re.match(ipv4_pattern, EndIP):
                ip1 = str(StartIP + " " + EndIP)
                print("Valid IPv4 address range!")
                break  # Add break here to exit the loop
            else:
                print(Fore.LIGHTRED_EX + "Invalid IPv4 address range.")

        # Loop for continuously prompting user for valid port range
        while True:
            StartPort = input('Enter Start Port : ')
            EndPort = input('Enter End Port : ')
            if re.match(port_pattern, StartPort) and re.match(port_pattern, EndPort):
                port1 = str(StartPort + "-" + EndPort)
                print(Fore.LIGHTYELLOW_EX + "Scanning: ", end="")
                print(Fore.LIGHTBLUE_EX + f'{StartIP} - {EndIP} ', end="")
                print(Fore.LIGHTYELLOW_EX + ", Port Range: ", end="")
                print(Fore.LIGHTBLUE_EX + f'{port1}')
                print("Processing..")
                Port_Scanner()
                break  # Add break here to exit the loop
            else:
                print(Fore.LIGHTRED_EX + "Invalid Port , ports are only between 1-65535")
        break  # Add break here to exit the outer loop

    else:
          print(Fore.LIGHTRED_EX + "Please choose a number from the options above")


