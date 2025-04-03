"""
Test suite for the stealth scanner module.

These tests validate the functionality of the SYN scanner without sending actual packets.
Most network operations are mocked to allow safe testing.
"""
import pytest
import sys
import os
import threading
from queue import Queue
from unittest.mock import MagicMock, patch

# Add the parent directory to the path to allow importing the module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.stealth_scanner import (
    syn_scan_port, check_privileges, stealth_worker, 
    stealth_scan_range, is_admin
)

# Mock common network responses
class MockPacketResponse:
    """Mock scapy packet response for testing."""
    def __init__(self, has_tcp=True, has_icmp=False, tcp_flags=0x12, icmp_type=None, icmp_code=None):
        self.has_tcp = has_tcp
        self.has_icmp = has_icmp
        self.tcp_flags = tcp_flags
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        
    def haslayer(self, layer):
        """Mock the haslayer method."""
        if layer.__name__ == 'TCP':
            return self.has_tcp
        if layer.__name__ == 'ICMP':
            return self.has_icmp
        return False
        
    def getlayer(self, layer):
        """Mock the getlayer method."""
        if layer.__name__ == 'TCP':
            # Create a TCP layer mock
            tcp_mock = MagicMock()
            tcp_mock.flags = self.tcp_flags
            return tcp_mock
        if layer.__name__ == 'ICMP':
            # Create an ICMP layer mock
            icmp_mock = MagicMock()
            icmp_mock.type = self.icmp_type
            icmp_mock.code = self.icmp_code
            return icmp_mock
        return None

@pytest.fixture
def mock_open_port():
    """Fixture for mocking an open port response (SYN-ACK)."""
    return MockPacketResponse(has_tcp=True, tcp_flags=0x12)  # 0x12 = SYN-ACK

@pytest.fixture
def mock_closed_port():
    """Fixture for mocking a closed port response (RST-ACK)."""
    return MockPacketResponse(has_tcp=True, tcp_flags=0x14)  # 0x14 = RST-ACK

@pytest.fixture
def mock_filtered_port():
    """Fixture for mocking a filtered port response (ICMP unreachable)."""
    return MockPacketResponse(has_tcp=False, has_icmp=True, icmp_type=3, icmp_code=1)

@pytest.fixture
def mock_no_response():
    """Fixture for mocking no response."""
    return None

# Tests for syn_scan_port function
@pytest.mark.parametrize("ip,port", [
    ("192.168.1.1", 80),
    ("10.0.0.1", 443),
    ("8.8.8.8", 53)
])
def test_syn_scan_port_open(monkeypatch, mock_open_port, ip, port):
    """Test syn_scan_port with open port responses."""
    # Mock sr1 to return an open port response
    monkeypatch.setattr("scapy.all.sr1", lambda *args, **kwargs: mock_open_port)
    
    # Test if the function correctly identifies an open port
    assert syn_scan_port(ip, port) is True

@pytest.mark.parametrize("ip,port", [
    ("192.168.1.1", 81),
    ("10.0.0.1", 444),
    ("8.8.8.8", 54)
])
def test_syn_scan_port_closed(monkeypatch, mock_closed_port, ip, port):
    """Test syn_scan_port with closed port responses."""
    # Mock sr1 to return a closed port response
    monkeypatch.setattr("scapy.all.sr1", lambda *args, **kwargs: mock_closed_port)
    
    # Test if the function correctly identifies a closed port
    assert syn_scan_port(ip, port) is False

def test_syn_scan_port_filtered(monkeypatch, mock_filtered_port):
    """Test syn_scan_port with filtered port responses."""
    # Mock sr1 to return a filtered port response
    monkeypatch.setattr("scapy.all.sr1", lambda *args, **kwargs: mock_filtered_port)
    
    # Test if the function correctly identifies a filtered port
    assert syn_scan_port("192.168.1.1", 80) is False

def test_syn_scan_port_no_response(monkeypatch, mock_no_response):
    """Test syn_scan_port with no responses."""
    # Mock sr1 to return no response
    monkeypatch.setattr("scapy.all.sr1", lambda *args, **kwargs: mock_no_response)
    
    # Test if the function correctly handles no response
    assert syn_scan_port("192.168.1.1", 80) is False

def test_syn_scan_port_exception(monkeypatch):
    """Test syn_scan_port error handling."""
    # Mock sr1 to raise an exception
    def mock_sr1(*args, **kwargs):
        raise Exception("Test exception")
    
    monkeypatch.setattr("scapy.all.sr1", mock_sr1)
    
    # Test if the function correctly handles exceptions
    assert syn_scan_port("192.168.1.1", 80) is False

# Tests for check_privileges function
def test_check_privileges_admin(monkeypatch):
    """Test check_privileges when running as admin."""
    # Mock is_admin to return True
    monkeypatch.setattr("core.stealth_scanner.is_admin", lambda: True)
    
    # Test if the function properly validates admin privileges
    assert check_privileges() is True

def test_check_privileges_not_admin(monkeypatch):
    """Test check_privileges when not running as admin."""
    # Mock is_admin to return False
    monkeypatch.setattr("core.stealth_scanner.is_admin", lambda: False)
    
    # Test if the function exits when not admin
    with pytest.raises(SystemExit):
        check_privileges()

# Tests for stealth_worker function
def test_stealth_worker(monkeypatch):
    """Test stealth_worker processing ports from queue."""
    # Create test data
    ip = "192.168.1.1"
    port_queue = Queue()
    port_queue.put(80)
    port_queue.put(443)
    results = []
    print_lock = threading.Lock()
    
    # Mock syn_scan_port to return True for port 80, False for 443
    def mock_scan(ip, port, *args, **kwargs):
        return port == 80
    
    monkeypatch.setattr("core.stealth_scanner.syn_scan_port", mock_scan)
    monkeypatch.setattr("core.stealth_scanner.COMMON_PORTS", {80: "HTTP", 443: "HTTPS"})
    
    # Run the worker
    stealth_worker(ip, port_queue, results, print_lock, quiet=True)
    
    # Verify results
    assert len(results) == 1
    assert results[0]["port"] == 80
    assert results[0]["service"] == "HTTP"
    assert port_queue.empty() is True

# Tests for stealth_scan_range function
def test_stealth_scan_range(monkeypatch):
    """Test stealth_scan_range function."""
    # Mock dependencies
    monkeypatch.setattr("core.stealth_scanner.SCAPY_AVAILABLE", True)
    monkeypatch.setattr("core.stealth_scanner.check_privileges", lambda: True)
    monkeypatch.setattr("core.stealth_scanner.MAX_THREADS", 10)
    
    # Mock thread creation to avoid actual threading
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", mock_thread)
    
    # Run scan with minimal parameters to test basic flow
    result = stealth_scan_range("192.168.1.1", 80, 85, quiet=True, show_progress=False)
    
    # Verify the function called thread creation with correct parameters
    assert mock_thread.call_count == 6  # 5 ports with max 10 threads
    
    # Due to mocking, the result will be empty but we can verify it's the expected type
    assert isinstance(result, list)

# Tests for is_admin function
@pytest.mark.parametrize("os_name,expected", [
    ("nt", True),   # Windows as admin
    ("posix", True)  # Unix as root
])
def test_is_admin(monkeypatch, os_name, expected):
    """Test is_admin function on different platforms."""
    # Mock os.name
    monkeypatch.setattr("os.name", os_name)
    
    if os_name == "nt":
        # Mock Windows admin check
        mock_isadmin = MagicMock(return_value=1 if expected else 0)
        monkeypatch.setattr("ctypes.windll.shell32.IsUserAnAdmin", mock_isadmin)
    else:
        # Mock Unix root check
        monkeypatch.setattr("os.geteuid", lambda: 0 if expected else 1000)
    
    # Test the function
    assert is_admin() is expected

def test_is_admin_exception(monkeypatch):
    """Test is_admin handling exceptions."""
    # Force an exception during check
    def mock_geteuid():
        raise AttributeError("Test exception")
    
    monkeypatch.setattr("os.geteuid", mock_geteuid)
    monkeypatch.setattr("os.name", "posix")
    
    # The function should catch the exception and return False
    assert is_admin() is False