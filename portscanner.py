import socket
import csv
from scapy.all import TCP, IP, sr1, sr, RandShort
from tqdm import tqdm
import datetime
import string

# generic banner function
def printBanner():
    banner = """
    d8888b.  .d88b.  d8888b. d888888b   .d8888.  .o88b.  .d8b.  d8b   db d8b   db d88888b d8888b. 
    88  `8D .8P  Y8. 88  `8D `~~88~~'   88'  YP d8P  Y8 d8' `8b 888o  88 888o  88 88'     88  `8D 
    88oodD' 88    88 88oobY'    88      `8bo.   8P      88ooo88 88V8o 88 88V8o 88 88ooooo 88oobY' 
    88~~~   88    88 88`8b      88        `Y8b. 8b      88~~~88 88 V8o88 88 V8o88 88~~~~~ 88`8b   
    88      `8b  d8' 88 `88.    88      db   8D Y8b  d8 88   88 88  V888 88  V888 88.     88 `88. 
    88       `Y88P'  88   YD    YP      `8888Y'  `Y88P' YP   YP VP   V8P VP   V8P Y88888P 88   YD                                                                                                                    
    """
    print(banner)

#  Likkle menu
def printMenu():
    menu = """
    Please choose from the following options:
    1. Slow Scan
    2. Stealth Scan
    """
    print(menu)

# This Function is used to validate if a port number is within the valid range
def validatePort(port):
    if port < 1 or port > 65535:
        raise ValueError("Invalid port number. It must be in the range of 1 to 65535.")

# Function to perform a normal port scan
def normalScan(target, startPort, endPort):
    results = []
    print(f"Starting Normal Scan on {target} from port {startPort} to {endPort}")
    try:
        for port in tqdm(range(startPort, endPort + 1)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    results.append((target, port, 'Open'))
                sock.close()
            except socket.error as e:
                print(f"Error occurred while scanning port {port}: {e}")
    except KeyboardInterrupt:
        print("\nScan interrupted by the user.")
    return results

# The stealthScan function performs a "discreet" port scan on a target IP address. 
# It generates TCP SYN packets and sends them to a range of ports on the target. 
# By analysing the responses received, it can determine whether each port is open or closed. 
# The results of the scan are returned, providing information about the status of the ports on the target IP address.
def stealthScan(target, startPort, endPort):
    results = []  # Initialise an empty list to store the scan results inside of
    print(f"Starting Stealth Scan on {target} from port {startPort} to {endPort}...")  # Print the scan information
    try:
        for port in tqdm(range(startPort, endPort + 1)):  # loop over the range of ports
            srcPort = RandShort()  # Generate a random source port
            try:
                p = IP(dst=target) / TCP(sport=srcPort, dport=port, flags='S')  # Craft the TCP SYN packet to begin
                resp = sr1(p, timeout=1)  # Send the packet and wait for a response
                if str(type(resp)) == "<class 'NoneType'>":  # Check if no response received
                    results.append((target, port, 'Closed'))  # Add closed port to the results list
                elif resp.haslayer(TCP):  # Check if response has TCP layer
                    if resp.getlayer(TCP).flags == 0x12:  # Check if TCP flags indicate an open port (SYN-ACK)
                        sendRst = sr(IP(dst=target) / TCP(sport=srcPort, dport=port, flags='AR'), timeout=1)  # Send TCP RST packet to close the connection
                        results.append((target, port, 'Open'))  # Add open port to the results list
                    elif resp.getlayer(TCP).flags == 0x14:  # Check if TCP flags indicate a closed port (RST)
                        results.append((target, port, 'Closed'))  # Add closed port to the results list
            except socket.error as e:  # Handle socket-related errors
                print(f"Error occurred while scanning port {port}: {e}")  # Print the error message
    except KeyboardInterrupt:  # Handle keyboard interrupt (Ctrl+C)
        print("\nScan stopped by the user.")  # Print the interrupt message
    return results  # Return the scan results


# Sanitise
def sanitiseFilenameTimestamp(timestamp):
    # ensure there are valid characters for the file name
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    # Create a new string by replacing invalid characters with underscores..happy days
    return ''.join(c if c in valid_chars else '_' for c in timestamp)

# Saves Result as a CSV functon
def saveResultsToFile(results):
    # Filter the results to include only the open ports..otherwise we get a reem of closed ports for every port scanned which is not fun
    open_ports = [r for r in results if r[2] == 'Open']
    # Get the current timestamp in the format 'YYYY-MM-DD HH:MM:SS'
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Sanitise the timestamp to ensure it can be used as part of a valid filename otherwise...errors
    sanitized_timestamp = sanitiseFilenameTimestamp(timestamp)
    # Construct the filename with the sanitised timestamp to avoid errors
    filename = f'scan_results_{sanitized_timestamp}.csv'
    # Open the file in write mode and handle it as 'f'
    with open(filename, 'w', newline='') as f:
        # Create a CSV writer object to write data to the file
        writer = csv.writer(f)
        # Write the timestamp as the first row in the file
        writer.writerow(['Timestamp'])
        # Write the timestamp value in the second row
        writer.writerow([timestamp])
        # Write an empty row for separation between the timestamp and the port scan results
        writer.writerow([])
        # Write the column headers for the port scan results
        writer.writerow(['Target', 'Port', 'Status'])
        # Write the open ports data to the CSV file
        writer.writerows(open_ports)

## Maino 
if __name__ == "__main__":
    try:
        printBanner()
        target = input("Enter target IP: ")
        while True:
            try:
                startPort = int(input("Enter start port: "))
                validatePort(startPort)
                endPort = int(input("Enter end port: "))
                validatePort(endPort)
                break
            except ValueError as e:
                print(e)
        printMenu()
        while True:
            try:
                scanType = int(input("Enter scan type: "))
                if scanType == 1:
                    results = normalScan(target, startPort, endPort)
                elif scanType == 2:
                    results = stealthScan(target, startPort, endPort)
                else:
                    raise ValueError("Invalid scan type. Please enter either '1' or '2'.")
                break
            except ValueError as e:
                print(e)
    except KeyboardInterrupt:
        print("\nScan interrupted by the user.")
        results = []
    except Exception as e:
        print(f"An error occurred: {e}")
        results = []
    saveResultsToFile(results)
