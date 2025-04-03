# Simple Network Scanner

A comprehensive network port scanner with vulnerability detection capabilities. This tool provides both standard TCP connect scanning and stealthy SYN scanning options, along with service detection and common security vulnerability checks.

## Features

- **Multiple Scanning Methods**:
  - Standard TCP port scanning
  - Stealth SYN scanning (requires root/admin privileges)
- **Service Identification**:
  - Banner grabbing
  - Service detection based on port numbers
- **Security Assessment**:
  - Checks for common vulnerabilities (FTP anonymous access, weak TLS configurations, etc.)
  - Security header analysis for web services
  - SSL/TLS configuration analysis
- **Reporting**:
  - Multiple output formats (TXT, JSON, HTML)
  - Detailed HTML reports with interactive elements
  - CSV export for integration with other tools
- **Performance**:
  - Multi-threaded scanning for speed
  - Configurable thread count and timeouts

## Requirements

- Python 3.6+
- Required packages:
  - rich (for enhanced console output)
  - scapy (optional, for stealth SYN scanning)

## Installation

### Using pip (recommended)

```bash
pip install simple-network-scanner
```

### From Source

```bash
git clone https://github.com/Zeusfail/Simple-Network-Scanner.git
cd Simple-Network-Scanner
pip install -e .
```

### Windows Note

For stealth scanning on Windows, you need:
- Administrator privileges
- Npcap or WinPcap installed (available from [npcap.com](https://npcap.com/))

## Usage

### Basic Usage

```bash
# Scan specific ports
netscanner -t 192.168.1.1 -p 80,443,8080

# Scan a range of ports
netscanner -t 192.168.1.1 -p 1-1000

# Scan common ports
netscanner -t 192.168.1.1 --top-ports 100
```

### Advanced Options

```bash
# Stealth SYN scan (requires root/admin)
sudo netscanner -t 192.168.1.1 -p 1-1000 --stealth

# Disable banner grabbing for faster scanning
netscanner -t 192.168.1.1 -p 1-1000 --no-banner

# Save results to HTML report
netscanner -t 192.168.1.1 -p 1-1000 --html
```

### Full Command Reference

```
usage: netscanner [-h] -t IP (-p PORT_RANGE | --top-ports {10,20,50,100,1000})
                 [-T THREADS] [--timeout TIMEOUT] [--no-banner]
                 [--no-vuln-check] [-s] [--txt] [--json] [--html]
                 [-o OUTPUT] [-q] [-v]
```

Run `netscanner -h` to see the complete list of options.

## Output Examples

The scanner can generate reports in multiple formats:

- **Text**: Simple text-based summary
- **JSON**: Structured data for programmatic analysis
- **HTML**: Interactive report with expandable sections
- **CSV**: For import into spreadsheets or databases

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
