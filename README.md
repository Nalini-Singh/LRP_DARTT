
# Automated Penetration Testing Toolkit

## Overview
This toolkit automates key penetration testing tasks including network scanning, vulnerability assessment, exploit enumeration, and deployment using Metasploit.

## Features
- **Network Discovery:** Scan and graphically visualize active devices on a network.
- **Vulnerability Assessment:** Detect open ports, running services, and associated CVEs.
- **Metasploit Integration:** Enumerate exploits and launch them directly.
- **Automated Reporting:** Generate professional reports in PDF and Markdown formats.
- **Session Management:** Historical tracking using SQLite.
- **Detailed Logging:** Audit trails for compliance and troubleshooting.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
Run the main script:
```bash
python main.py
```

## Project Structure
```
pentest_tool/
├── main.py
├── scanner.py
├── exploits.py
├── reports.py
├── sessions.py
├── logs.py
├── requirements.txt
└── data/
    ├── pentest.db
    └── logs/
```

## Dependencies
- python-nmap
- pymetasploit3
- fpdf
- markdown
- networkx
- matplotlib
- sqlite3

Ensure Metasploit Framework is installed and RPC is enabled.

## License
MIT License
