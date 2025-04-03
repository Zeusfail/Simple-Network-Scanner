"""
Network stealth scanner module using SYN scanning technique.

This module provides functionality for stealthy port scanning using TCP SYN packets.
It requires administrator/root privileges to run and depends on the Scapy library
for low-level packet manipulation.
"""
import random
import sys
import os
import time
import threading
from queue import Queue
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, conf, ICMP
from utils.config import *

def syn_scan_port(ip, port, timeout=2, rate_limit=0):
    """
    Performs a stealthy SYN scan on a specific port.
    
    Args:
        ip (str): Target IP address
        port (int): Target port number
        timeout (float): Timeout for waiting for a response in seconds
        rate_limit (float): Optional delay between packets in seconds
    
    Returns:
        bool: True if port is open, False otherwise
    """
    # Random source port for better stealth
    src_port = random.randint(1025, 65534)
    
    # Disable Scapy output
    conf.verb = 0
    
    try:
        # Add optional rate limiting
        if rate_limit > 0:
            time.sleep(rate_limit)
            
        # Build and send SYN packet
        packet = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
        response = sr1(packet, timeout=timeout, retry=0)
        
        # Analyze the response
        if response is None:
            # No response, probably filtered or closed
            return False
        
        elif response.haslayer(ICMP):
            # ICMP response might indicate filtered port
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                # Port is filtered (various ICMP unreachable codes)
                return False
        
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            
            # Check TCP flags
            if tcp_layer.flags & 0x12:  # SYN-ACK (0x12 = 0x02 | 0x10)
                # Port is open, send RST to properly terminate
                rst_packet = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R")
                sr1(rst_packet, timeout=1, verbose=0)
                return True
                
            elif tcp_layer.flags & 0x14:  # RST-ACK
                # Port closed
                return False
        
        # Default to closed
        return False
    except Exception as e:
        # Handle any unexpected errors
        print(f"Error scanning port {port}: {e}")
        return False

def check_privileges():
    """
    Checks if the script has the necessary administrator privileges.
    
    Returns:
        bool: True if the script has admin privileges, False otherwise
    
    Raises:
        SystemExit: If the script lacks the required privileges
    """
    if sys.platform != "win32":  # Unix/Linux systems
        try:
            if os.geteuid() != 0:
                print("Error: Stealth scan requires root privileges")
                sys.exit(1)
        except AttributeError:
            # If geteuid is not available
            if not is_admin():
                print("Error: Stealth scan requires root privileges")
                sys.exit(1)
    else:  # Windows
        if not is_admin():
            print("Error: Stealth scan requires administrator privileges")
            print("Please run the Command Prompt as Administrator and try again")
            sys.exit(1)
    return True

def stealth_worker(ip, port_queue, results, print_lock, timeout=2, rate_limit=0, quiet=False):
    """
    Worker function executed by each thread for stealthy port scanning.
    
    Args:
        ip (str): Target IP address
        port_queue (Queue): Queue of ports to scan
        results (list): Shared list to store scan results
        print_lock (Lock): Thread lock for console output
        timeout (float): Scan timeout in seconds
        rate_limit (float): Delay between scans in seconds
        quiet (bool): Whether to suppress console output
    """
    while not port_queue.empty():
        try:
            port = port_queue.get()
            
            if syn_scan_port(ip, port, timeout, rate_limit):
                # Port is open
                service = COMMON_PORTS.get(port, "Unknown")
                
                if not quiet:
                    with print_lock:
                        print(f"Port {port} is open - Service: {service}")
                
                # Store port information
                results.append({
                    'port': port,
                    'service': service,
                    'banner': None,
                    'vulnerabilities': []
                })
            
            port_queue.task_done()
        except Exception as e:
            with print_lock:
                print(f"Error in worker thread: {e}")
            port_queue.task_done()

def stealth_scan_range(ip, start_port, end_port, threads=None, timeout=2, 
                       rate_limit=0, quiet=False, show_progress=True,  callback=None):
    """
    Scans a range of ports on an IP address using stealthy SYN scans.
    
    Args:
        ip (str): Target IP address
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): Number of threads to use (None = auto)
        timeout (float): Scan timeout in seconds
        rate_limit (float): Delay between packets to avoid detection
        quiet (bool): Whether to suppress console output
        show_progress (bool): Whether to show scan progress
    
    Returns:
        list: List of dictionaries containing scan results
    """
    if not SCAPY_AVAILABLE:
        print("Error: Stealth mode requires the scapy library. Install it with: pip install scapy")
        sys.exit(1)
    
    # Check for admin privileges
    check_privileges()
        
    if not quiet:
        print(f"Stealth scanning {ip} from port {start_port} to {end_port} using SYN packets...")
    start_time = time.time()
    
    # Initialize queue and results list
    port_queue = Queue()
    results = []
    print_lock = threading.Lock()
    
    # Fill queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    # Determine thread count
    num_ports = end_port - start_port + 1
    max_stealth_threads = min(MAX_THREADS, 25)  # Limit threads for stealth mode
    num_threads = threads if threads else min(num_ports, max_stealth_threads)
    
    # Create and start threads
    threads_list = []
    for _ in range(num_threads):
        thread = threading.Thread(
            target=stealth_worker, 
            args=(ip, port_queue, results, print_lock, timeout, rate_limit, quiet)
        )
        thread.daemon = True
        threads_list.append(thread)
        thread.start()
    
    # Show progress if requested
    total_ports = num_ports
    if show_progress and not quiet:
        while not port_queue.empty():
            remaining = port_queue.qsize()
            scanned = total_ports - remaining
            percent = (scanned / total_ports) * 100
            sys.stdout.write(f"\rProgress: {scanned}/{total_ports} ports scanned ({percent:.1f}%)  ")
            sys.stdout.flush()
            time.sleep(0.5)
    
    # Wait for all ports to be scanned
    port_queue.join()
    
    # Wait for all threads to finish
    for thread in threads_list:
        thread.join()
    
    elapsed_time = time.time() - start_time
    if not quiet:
        if show_progress:
            sys.stdout.write("\r" + " " * 60 + "\r")  # Clear progress line
        print(f"\nStealth scan completed in {elapsed_time:.2f} seconds")
        print(f"Found {len(results)} open ports")
    
    return sorted(results, key=lambda x: x['port'])

def is_admin():
    """
    Checks if the script is running with administrator privileges.
    
    Returns:
        bool: True if running as admin/root, False otherwise
    """
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/Mac
            return os.geteuid() == 0
    except:
        return False