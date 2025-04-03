# Simple Network Scanner

A comprehensive network port scanner with vulnerability detection capabilities.

## Features
- Standard TCP port scanning
- Stealth SYN scanning (requires root/admin privileges)
- Service banner grabbing
- Common vulnerability checks
- Multiple output formats (TXT, JSON, HTML)
- Multi-threaded scanning for speed

## Requirements
- Python 3.6+
- Scapy (optional, for stealth scanning)

## Installation

### From Source
```bash
git clone https://github.com/yourusername/simple-network-scanner.git
cd simple-network-scanner
pip install -e .