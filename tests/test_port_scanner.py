import pytest
import socket
import threading
from queue import Queue
from unittest.mock import patch, MagicMock, call

from core.port_scanner import (
    validate_ip, validate_port, scan_port, _scan_common, 
    scan_ports, scan_specific_ports, scan_range, worker
)


class TestIPValidation:
    """Tests pour la validation d'adresses IP"""

    def test_valid_ipv4(self):
        """Test avec des adresses IPv4 valides"""
        valid_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "127.0.0.1", "255.255.255.255"]
        for ip in valid_ips:
            assert validate_ip(ip) is True

    def test_invalid_ipv4(self):
        """Test avec des adresses IP invalides"""
        invalid_ips = [
            "256.0.0.1",  # Octet > 255
            "192.168.1",  # Incomplet
            "192.168.1.1.1",  # Trop d'octets
            "192.168.a.1",  # Caractère non numérique
            "",  # Chaîne vide
            "localhost",  # Nom de domaine (non IP)
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"  # IPv6
        ]
        for ip in invalid_ips:
            assert validate_ip(ip) is False


class TestPortValidation:
    """Tests pour la validation des ports"""

    def test_valid_ports(self):
        """Test avec des ports valides"""
        valid_ports = [1, 80, 443, 8080, 22, 65535]
        for port in valid_ports:
            assert validate_port(port) is True

    def test_invalid_ports(self):
        """Test avec des ports invalides"""
        invalid_ports = [
            0,  # En dessous de la plage
            65536,  # Au-dessus de la plage
            -1,  # Négatif
            "80",  # Type incorrect (string)
            None,  # None
            3.14  # Float
        ]
        for port in invalid_ports:
            assert validate_port(port) is False


@patch('socket.socket')
class TestScanPort:
    """Tests pour la fonction scan_port avec mock de socket"""

    def test_open_port(self, mock_socket):
        """Test avec un port ouvert (connect_ex retourne 0)"""
        # Configurer le mock pour simuler un port ouvert
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 0
        mock_socket.return_value = mock_socket_instance

        # Tester scan_port avec une IP et un port valides
        result = scan_port("192.168.1.1", 80)
        
        # Vérifier que le résultat est True (port ouvert)
        assert result is True
        # Vérifier que socket.connect_ex a été appelé avec les bons arguments
        mock_socket_instance.connect_ex.assert_called_once_with(("192.168.1.1", 80))

    def test_closed_port(self, mock_socket):
        """Test avec un port fermé (connect_ex retourne une erreur)"""
        # Configurer le mock pour simuler un port fermé
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 1  # N'importe quelle valeur non-zéro
        mock_socket.return_value = mock_socket_instance

        # Tester scan_port avec une IP et un port valides
        result = scan_port("192.168.1.1", 80)
        
        # Vérifier que le résultat est False (port fermé)
        assert result is False

    def test_socket_error(self, mock_socket):
        """Test avec une erreur socket pendant le scan"""
        # Configurer le mock pour lever une exception
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.side_effect = socket.error("Test error")
        mock_socket.return_value = mock_socket_instance

        # Tester scan_port avec une IP et un port valides
        result = scan_port("192.168.1.1", 80)
        
        # Vérifier que le résultat est False (erreur traitée)
        assert result is False

    def test_invalid_ip(self, mock_socket):
        """Test avec une IP invalide"""
        with pytest.raises(ValueError) as excinfo:
            scan_port("999.999.999.999", 80)
        assert "Adresse IP invalide" in str(excinfo.value)

    def test_invalid_port(self, mock_socket):
        """Test avec un port invalide"""
        with pytest.raises(ValueError) as excinfo:
            scan_port("192.168.1.1", 99999)
        assert "Numéro de port invalide" in str(excinfo.value)


@patch('core.port_scanner.scan_port')
@patch('core.port_scanner.get_service_banner')
@patch('core.port_scanner.check_vulnerabilities')
class TestScanCommon:
    """Tests pour la fonction _scan_common"""

    def setup_method(self):
        """Configuration commune pour chaque test"""
        self.port_queue = Queue()
        self.results = []
        self.print_lock = threading.Lock()
        self.ip = "192.168.1.1"
        
        # Remplir la queue avec quelques ports
        for port in [80, 443, 22]:
            self.port_queue.put(port)

    def test_scan_with_open_ports(self, mock_check_vulnerabilities, mock_get_banner, mock_scan_port):
        """Test _scan_common avec des ports ouverts"""
        # Configurer les mocks
        mock_scan_port.return_value = True  # Simuler des ports ouverts
        mock_get_banner.return_value = "Apache/2.4.41"
        mock_check_vulnerabilities.return_value = [
            {"type": "CVE-2021-1234", "severity": "High"}
        ]

        # Exécuter _scan_common
        _scan_common(self.ip, self.port_queue, self.results, self.print_lock, 1.0, quiet=True)

        # Vérifier les résultats
        assert len(self.results) == 3  # 3 ports scannés et ouverts
        assert all(result['banner'] == "Apache/2.4.41" for result in self.results)
        assert all(len(result['vulnerabilities']) == 1 for result in self.results)

    def test_scan_with_closed_ports(self, mock_check_vulnerabilities, mock_get_banner, mock_scan_port):
        """Test _scan_common avec des ports fermés"""
        # Configurer les mocks
        mock_scan_port.return_value = False  # Simuler des ports fermés

        # Exécuter _scan_common
        _scan_common(self.ip, self.port_queue, self.results, self.print_lock, 1.0, quiet=True)

        # Vérifier les résultats
        assert len(self.results) == 0  # Aucun résultat car tous les ports sont fermés
        # Vérifier que scan_port a été appelé pour tous les ports
        assert mock_scan_port.call_count == 3

    def test_scan_with_stop_event(self, mock_check_vulnerabilities, mock_get_banner, mock_scan_port):
        """Test _scan_common avec un événement d'arrêt"""
        # Configurer les mocks
        mock_scan_port.return_value = True
        
        # Créer un événement d'arrêt déjà activé
        stop_event = threading.Event()
        stop_event.set()

        # Exécuter _scan_common
        _scan_common(self.ip, self.port_queue, self.results, self.print_lock, 1.0, 
                   quiet=True, stop_event=stop_event)

        # Vérifier que aucun scan n'a été effectué (arrêt immédiat)
        assert not mock_scan_port.called
        assert len(self.results) == 0


@patch('core.port_scanner._scan_common')
class TestScanPorts:
    """Tests pour les fonctions de scan principales"""

    def test_scan_ports_valid_input(self, mock_scan_common):
        """Test scan_ports avec des paramètres valides"""
        # Configurer le mock pour simuler le comportement
        def side_effect(*args, **kwargs):
            # Ajouter quelques résultats simulés
            results = args[2]  # Le 3ème argument est 'results'
            results.append({'port': 80, 'service': 'HTTP'})
            
        mock_scan_common.side_effect = side_effect

        # Exécuter scan_ports
        result = scan_ports("192.168.1.1", [80, 443], quiet=True)
        
        # Vérifier les résultats
        assert len(result) == 1  # Un port simulé ouvert
        assert result[0]['port'] == 80

    def test_scan_ports_invalid_ip(self, mock_scan_common):
        """Test scan_ports avec une IP invalide"""
        with pytest.raises(ValueError) as excinfo:
            scan_ports("999.999.999.999", [80, 443])
        assert "Adresse IP invalide" in str(excinfo.value)

    def test_scan_ports_invalid_port(self, mock_scan_common):
        """Test scan_ports avec des ports invalides"""
        with pytest.raises(ValueError) as excinfo:
            scan_ports("192.168.1.1", [80, 99999])
        assert "Numéro de port invalide" in str(excinfo.value)

    def test_scan_range(self, mock_scan_common):
        """Test scan_range avec paramètres valides"""
        # Configurer le mock
        def side_effect(*args, **kwargs):
            results = args[2]
            results.append({'port': 80, 'service': 'HTTP'})
            
        mock_scan_common.side_effect = side_effect

        # Exécuter scan_range
        result = scan_range("192.168.1.1", 80, 85, quiet=True)
        
        # Vérifier les résultats et que scan_ports a été appelé avec la plage correcte
        assert len(result) == 1
        
    def test_scan_specific_ports(self, mock_scan_common):
        """Test scan_specific_ports avec paramètres valides"""
        # Configurer le mock
        def side_effect(*args, **kwargs):
            results = args[2]
            for port in [22, 80]:
                results.append({'port': port, 'service': 'Unknown'})
            
        mock_scan_common.side_effect = side_effect

        # Exécuter scan_specific_ports
        result = scan_specific_ports("192.168.1.1", [22, 80, 443], quiet=True)
        
        # Vérifier les résultats
        assert len(result) == 2
        assert sorted([r['port'] for r in result]) == [22, 80]


class TestBackwardCompatibility:
    """Tests pour la rétrocompatibilité"""

    @patch('core.port_scanner._scan_common')
    def test_worker_function(self, mock_scan_common):
        """Test que worker appelle _scan_common avec les bons paramètres"""
        # Préparer les arguments
        ip = "192.168.1.1"
        port_queue = Queue()
        results = []
        print_lock = threading.Lock()
        
        # Appeler worker
        worker(ip, port_queue, results, print_lock)
        
        # Vérifier que _scan_common a été appelé avec les bons arguments
        mock_scan_common.assert_called_once_with(ip, port_queue, results, print_lock, timeout=1, quiet=False)