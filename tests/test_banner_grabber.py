import pytest
import socket
from unittest.mock import patch, MagicMock
import sys
import os

# Ajout du répertoire parent au path pour pouvoir importer les modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.banner_grabber import get_service_banner, Protocol, get_protocol_by_port

class TestBannerGrabber:
    
    def test_get_protocol_by_port(self):
        """Teste l'identification des protocoles par port"""
        assert get_protocol_by_port(80) == Protocol.HTTP
        assert get_protocol_by_port(22) == Protocol.SSH
        assert get_protocol_by_port(9999) is None
    
    @patch('socket.socket')
    def test_successful_banner_grab(self, mock_socket):
        """Teste la récupération réussie d'une bannière"""
        # Configuration du mock
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        
        # Appel de la fonction
        result = get_service_banner("192.168.1.1", 22)
        
        # Vérification des résultats
        assert result == "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        mock_socket_instance.connect.assert_called_once_with(("192.168.1.1", 22))
        mock_socket_instance.settimeout.assert_called_once_with(2)
    
    @patch('socket.socket')
    def test_http_request_formatting(self, mock_socket):
        """Teste la formation correcte de la requête HTTP"""
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"
        
        get_service_banner("192.168.1.1", 80)
        
        # Vérifie que la requête HTTP a été correctement formatée
        sent_data = mock_socket_instance.send.call_args[0][0]
        assert b"Host: 192.168.1.1" in sent_data
        assert b"HEAD / HTTP/1.1" in sent_data
    
    @patch('socket.socket')
    def test_timeout_handling(self, mock_socket):
        """Teste la gestion des timeouts"""
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.side_effect = socket.timeout
        
        result = get_service_banner("192.168.1.1", 80)
        
        assert result is None
        mock_socket_instance.close.assert_called_once()
    
    @patch('socket.socket')
    def test_connection_refused(self, mock_socket):
        """Teste la gestion des connexions refusées"""
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.side_effect = ConnectionRefusedError
        
        result = get_service_banner("192.168.1.1", 80)
        
        assert result is None
        mock_socket_instance.close.assert_called_once()
    
    @patch('socket.socket')
    def test_custom_request(self, mock_socket):
        """Teste l'envoi d'une requête personnalisée"""
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.recv.return_value = b"CUSTOM RESPONSE"
        
        custom_req = b"CUSTOM REQUEST\r\n"
        result = get_service_banner("192.168.1.1", 1234, custom_request=custom_req)
        
        assert result == "CUSTOM RESPONSE"
        mock_socket_instance.send.assert_called_once_with(custom_req)