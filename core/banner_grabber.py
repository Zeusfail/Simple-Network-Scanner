import socket
import ssl
from enum import Enum
from typing import Optional, Dict, Union

class Protocol(Enum):
    """Énumération des protocoles réseau courants"""
    HTTP = 80
    HTTPS = 443
    SSH = 22
    FTP = 21
    SMTP = 25
    POP3 = 110
    IMAP = 143
    TELNET = 23
    DNS = 53
    HTTP_ALT = 8080

# Configuration des requêtes par protocole
DEFAULT_REQUESTS = {
    Protocol.HTTP: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BannerGrabber/1.0\r\n\r\n",
    Protocol.HTTPS: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BannerGrabber/1.0\r\n\r\n",
    Protocol.HTTP_ALT: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BannerGrabber/1.0\r\n\r\n",
    Protocol.SSH: None,
    Protocol.FTP: None,
    Protocol.SMTP: None,
    Protocol.POP3: None,
    Protocol.IMAP: None,
    Protocol.TELNET: b"\r\n",
}

def get_protocol_by_port(port: int) -> Optional[Protocol]:
    """
    Détermine le protocole en fonction du numéro de port
    
    Args:
        port: Le numéro de port à analyser
        
    Returns:
        Le protocole correspondant au port ou None si aucune correspondance
    """
    try:
        return next((p for p in Protocol if p.value == port), None)
    except StopIteration:
        return None

def get_service_banner(ip: str, port: int, timeout: float = 2, 
                      use_ssl: bool = False,
                      custom_request: Optional[bytes] = None) -> Optional[str]:
    """
    Tente de récupérer la bannière du service sur un port spécifique.
    
    Args:
        ip: L'adresse IP du serveur cible
        port: Le port à scanner
        timeout: Délai d'attente avant abandon de la connexion (en secondes)
        use_ssl: Indique si la connexion doit utiliser SSL/TLS
        custom_request: Requête personnalisée à envoyer au lieu de la requête par défaut
        
    Returns:
        La bannière du service sous forme de chaîne de caractères, ou None si aucune bannière n'a pu être récupérée
    """
    s = None
    try:
        # Création du socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Utilisation de SSL/TLS si demandé
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=ip)
        
        # Détermine le protocole
        protocol = get_protocol_by_port(port)
        
        # Décide quelle requête envoyer
        request_data = None
        if custom_request:
            request_data = custom_request
        elif protocol and protocol in DEFAULT_REQUESTS:
            request_template = DEFAULT_REQUESTS[protocol]
            if request_template:
                # Formater la requête avec l'adresse IP
                request_data = request_template.replace(b"{host}", ip.encode())
        elif port not in [p.value for p in Protocol]:
            # Pour les ports non standards, envoi d'un retour chariot
            request_data = b"\r\n"
        
        # Envoi de la requête si nécessaire
        if request_data:
            s.send(request_data)
        
        # Récupération des données (max 1024 octets)
        banner = s.recv(1024)
        
        # Nettoyage et décodage de la bannière
        if banner:
            try:
                return banner.strip().decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                # En cas d'échec du décodage, retourner une représentation hexadécimale
                return f"HEX:{banner.hex()}"
        return None
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception as e:
        # Capture des exceptions non anticipées
        print(f"Erreur inattendue lors de la récupération de la bannière {ip}:{port}: {str(e)}")
        return None
    finally:
        if s:
            try:
                s.close()
            except:
                pass