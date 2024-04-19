import socket  # Importing the socket module for network communication
import time  # Importing the time module for timing the scan
import threading  # Importing the threading module for concurrent execution
from tqdm import tqdm  # Importing tqdm for the progress bar

# Dictionary to map port numbers to their respective protocols
PORT_PROTOCOLS = { # Mapping port numbers to common protocols
    20: "FTP - Data",
    21: "FTP - Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP - Server",
    68: "DHCP - Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "Kerberos",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/LPR",
    520: "RIP",
    631: "IPP/CUPS",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5061: "SIPS",
    5432: "PostgreSQL",
    5500: "VNC",
    5900: "VNC",
    8080: "HTTP - Alt"
    
}

def port_scan(target, port, timeout=1):
    """Function to perform a port scan on a target IP address and port.
    Returns a list of protocols if the port is open, None otherwise."""
    protocols = []
    # Scanning TCP protocol
    if scan_tcp(target, port, timeout):
        protocol = PORT_PROTOCOLS.get(port, "?")  # Get protocol name, "?" if unknown
        protocols.append(protocol)
    # Scanning UDP protocol
    if scan_udp(target, port, timeout):
        protocol = PORT_PROTOCOLS.get(port, "?")  # Get protocol name, "?" if unknown
        protocols.append(protocol)
    return protocols if protocols else None

def scan_tcp(target, port, timeout=1):
    """Function to scan a port using TCP protocol."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))  # Attempting to connect to the target IP and port
        s.close()  # Closing the socket
        return True  # Port is open
    except Exception as e:
        s.close()  # Closing the socket in case of an exception
        return False  # Port is closed

def scan_udp(target, port, timeout=1):
    """Function to scan a port using UDP protocol."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b'', (target, port))  # Sending an empty UDP packet
        s.close()  # Closing the socket
        return True  # Port is open
    except Exception as e:
        s.close()  # Closing the socket in case of an exception
        return False  # Port is closed

def get_target_and_ports():
    """Function to get the target IP address or domain name and ports from the user."""
    while True:
        # Prompting the user to select the target type (IP address or domain name)
        print("\nEnter the target:")
        print("1. Scan by IP address")
        print("2. Scan by domain name")
        choice = input("Enter your choice (1 or 2): ")
        if choice == "1":
            target = input('Enter an IP address to scan: ')
            try:
                socket.inet_aton(target)  # Checking if the input is a valid IP address
                break  # Valid IP address entered
            except socket.error:
                print("Invalid IP address. Please try again.")
        elif choice == "2":
            target = input('Enter a domain name to scan: ')
            try:
                target = socket.gethostbyname(target)  # Resolving the domain name to an IP address
                break  # Valid domain name entered
            except socket.gaierror:
                print("Invalid domain name. Please try again.")
        else:
            print("Invalid choice. Please enter 1 or 2.")

    ports = []
    # Prompting the user to select the method of port entry (specific ports or a range of ports)
    print("\nSelect port entry method:")
    print("1. Scan specific ports")
    print("2. Scan a range of ports")
    entry_method = input("Enter your choice (1 or 2): ")
    if entry_method == "1":
        while True:
            # Prompting the user to enter specific ports
            port_input = input("Enter specific ports (comma-separated list, e.g., '80, 443'): ").strip()
            try:
                ports.extend(map(int, port_input.split(",")))  # Converting comma-separated input to a list of integers
                break  # Valid ports entered
            except ValueError:
                print("Invalid input. Please enter valid port numbers.")
    elif entry_method == "2":
        try:
            # Prompting the user to enter a port range
            start_port = int(input("Enter the start port of the range: "))
            end_port = int(input("Enter the end port of the range: "))
            if start_port < 0 or start_port > 65535 or end_port < 0 or end_port > 65535 or start_port > end_port:
                print("Invalid port range. Please enter valid start and end ports.")
            else:
                ports.extend(range(start_port, end_port + 1))  # Adding ports in the specified range to the list
        except ValueError:
            print("Invalid input. Please enter valid port numbers.")
    else:
        print("Invalid choice. Please enter 1 or 2.")

    return target, sorted(set(ports))  # Returning the target and sorted list of unique ports

def scan_ports(target, ports, progress_bar, show_protocols):
    """Function to scan the ports in a threaded manner."""
    open_ports = {}
    for port in ports:
        protocols = port_scan(target, port)  # Getting protocols for open ports
        if protocols:
            open_ports[port] = protocols if show_protocols else None  # Storing open ports and their protocols
        progress_bar.update(1)  # Updating progress bar
    return open_ports

def main():
    """Main function to run the port scanning program."""
    print("\n--- Port Scanner ---")
    target, ports = get_target_and_ports()  # Getting target and ports from the user
    show_protocols = input("\nDo you want to display protocols for open ports? (yes/no): ").lower() == 'yes' # Asking the user if they want to display protocols for open ports
    print('\nStarting scan on:', target)  # Displaying the target IP address/domain name

    
    

    start = time.time()  # Recording the start time of the scan

    total_ports = len(ports)
    progress_bar = tqdm(total=total_ports, desc="Scanning", unit="port")  # Initializing progress bar

    num_threads = min(100, total_ports)  # Limiting the number of threads to prevent excessive resource consumption
    chunk_size = (total_ports + num_threads - 1) // num_threads
    thread_chunks = [ports[i:i + chunk_size] for i in range(0, total_ports, chunk_size)]

    open_ports = {}
    threads = []
    # Creating threads to scan ports concurrently
    for chunk in thread_chunks:
        thread = threading.Thread(target=lambda: open_ports.update(scan_ports(target, chunk, progress_bar, show_protocols)))
        thread.start()
        threads.append(thread)

    # Waiting for all threads to finish
    for thread in threads:
        thread.join()

    progress_bar.close()  # Closing progress bar

    # Displaying open ports and their protocols (if requested by the user)
    if open_ports:
        print("\nOpen Ports:")
        for port, protocols in sorted(open_ports.items()):
            if protocols:
                protocol_str = ", ".join(protocols)
                print(f'Port {port}: {protocol_str}')  # Displaying port number and associated protocols
            else:
                print(f'Port {port}')  # Displaying only port number if protocols are not requested
    else:
        print("\nNo open ports found.")  # Displaying a message if no open ports are found

    end = time.time()  # Recording the end time of the scan
    print(f'Time taken: {end - start:.2f} seconds')  # Calculating and displaying the total time taken for the scan

if __name__ == "__main__":
    main()  # Calling the main function when the script is executed
