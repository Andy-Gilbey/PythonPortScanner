# Network Port Scanner

## Summary
This port scanner script, I developed during the summer break between my second and third years of college as a "self-initiated" project. 
The creation of this tool was to strengthen my understanding of Python programming and penetration testing techniques as prepatory work ahead of a Penetration Testing module which was to be part of my third year course. 

## Features
- **Normal Scan**: Performs a basic port scan.
- **Stealth Scan**: Uses TCP SYN packets for a less detectable port scan.
- **Dynamic Range**: Allows user-defined port ranges.
- **Results Saving**: Automatically saves the scan results to a CSV file.

## Prerequisites
Before running the script, ensure you have the following installed:
- Python 3.x
- Scapy
- tqdm

You can install the necessary libraries using pip, e.g.:

```bash
pip install scapy tqdm
```

## How to Run the Script
To run the script, follow these steps:

- **Open your terminal or command prompt.**
- **Navigate to the directory containing the script.** Use the `cd` command to change to the directory where you've saved `network_port_scanner.py`.

  Example:
  ```bash
  cd path/to/your/script
 ```

- **Run the script using the following command:**
  
  ```bash
  python network_port_scanner.py
 ```
- **Follow the on-screen prompts:**
  - Enter the target IP address when prompted.
  - Enter the start port and end port for the range you wish to scan.
- **Choose the type of scan you want to perform:**
  - Type `1` for a Normal Scan.
  - Type `2` for a Stealth Scan.
- **Results will be automatically saved in a CSV file** in the same directory as the script. The file will be named `scan_results_<timestamp>.csv`.

## Handling Results
The script outputs a CSV file named `scan_results_<timestamp>.csv` containing details of all open ports found during the scan. You can open this file with any text editor or spreadsheet software to review the results.

## License

## Legal Notice and Responsible Use
Before utilising this port scanner, it is imperative to obtain the explicit permission from the network owners. 
Unauthorised use of this tool to scan networks may be considered unlawful/unethical in many jurisdictions. The user of this tool is solely responsible for ensuring that their actions comply with applicable local, national, and international laws. 
Misuse of this tool could violate laws such as those protecting against unauthorised access to systems or even data privacy. In some regions, this may include legislation akin to the European GDPR, in the U.S. Computer Fraud and Abuse Act.
Users are urged to use this tool responsibly as well as ethically, with a full awareness of any legal implications which include their potential penalties. Always confirm that your scanning activities are legal and of course authorised by any relevant parties before proceeding.
Always conduct scanning activities responsibly and ethically, ensuring that all activities are legal and authorised by the rightful owners or administrators of the network and devices involved.


  
