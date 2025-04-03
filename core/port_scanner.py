import socket
import time
import threading
import ipaddress
from queue import Queue
from typing import List, Dict, Any, Optional, Union
from core.banner_grabber import get_service_banner
from core.vulnerability_checker import check_vulnerabilities
from utils.config import MAX_THREADS, COMMON_PORTS


def validate_ip(ip: str) -> bool:
    """
    Valide si une chaîne est une adresse IPv4 valide.
    
    Args:
        ip: L'adresse IP à valider
    
    Returns:
        bool: True si l'IP est valide, False sinon
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Valide si un port est dans la plage valide (1-65535).
    
    Args:
        port: Le numéro de port à valider
        
    Returns:
        bool: True si le port est valide, False sinon
    """
    return isinstance(port, int) and 1 <= port <= 65535


def scan_port(ip: str, port: int, timeout: float = 1) -> bool:
    """
    Tente une connexion sur un port spécifique.
    
    Args:
        ip: L'adresse IP cible
        port: Le port à scanner
        timeout: Délai d'attente en secondes avant d'abandonner la connexion
        
    Returns:
        bool: True si le port est ouvert, False sinon
        
    Raises:
        ValueError: Si l'IP ou le port sont invalides
    """
    if not validate_ip(ip):
        raise ValueError(f"Adresse IP invalide: {ip}")
    if not validate_port(port):
        raise ValueError(f"Numéro de port invalide: {port}")
        
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error as e:
        print(f"Erreur lors du scan du port {port}: {e}")
        return False


def _scan_common(ip: str, port_queue: Queue, results: List[Dict[str, Any]], 
                print_lock: threading.Lock, timeout: float, quiet: bool = False,
                stop_event: Optional[threading.Event] = None) -> None:
    """
    Fonction de travail commune utilisée par les threads de scan.
    
    Args:
        ip: L'adresse IP cible
        port_queue: La file d'attente contenant les ports à scanner
        results: La liste où stocker les résultats
        print_lock: Verrou pour éviter les problèmes d'affichage entre threads
        timeout: Délai d'attente pour les connexions
        quiet: Si True, supprime l'affichage des résultats en temps réel
        stop_event: Événement pour arrêter prématurément le scan
    """
    while not port_queue.empty():
        # Vérifier si on a demandé l'arrêt du scan
        if stop_event and stop_event.is_set():
            break
            
        try:
            port = port_queue.get(block=False)  # Non-bloquant pour gérer l'arrêt proprement
        except Queue.Empty:
            continue  # La queue peut devenir vide entre la vérification et l'obtention
            
        try:
            if scan_port(ip, port, timeout):
                # Port ouvert, récupérer la bannière
                banner = get_service_banner(ip, port)
                
                # Déterminer le service probable
                service = COMMON_PORTS.get(port, "Unknown")
                
                # Effectuer les tests de vulnérabilités
                vulnerabilities = check_vulnerabilities(ip, port, service)
                
                if not quiet:
                    with print_lock:
                        print(f"Port {port} is open - Service: {service}")
                        if banner:
                            # Limiter l'affichage de la bannière pour éviter les outputs trop longs
                            banner_preview = banner.replace('\n', ' ').replace('\r', '')
                            if len(banner_preview) > 100:
                                banner_preview = banner_preview[:97] + "..."
                            print(f"  Banner: {banner_preview}")
                        
                        if vulnerabilities:
                            print(f"  VULNERABILITIES FOUND ({len(vulnerabilities)}):")
                            for vuln in vulnerabilities:
                                print(f"    - {vuln['type']} [Severity: {vuln['severity']}]")
                
                # Stocker les informations complètes
                results.append({
                    'port': port,
                    'service': service,
                    'banner': banner,
                    'vulnerabilities': vulnerabilities
                })
        except Exception as e:
            with print_lock:
                print(f"Erreur lors du scan du port {port}: {e}")
        finally:
            port_queue.task_done()


def scan_ports(ip: str, ports: Union[List[int], range], timeout: float = 1, 
              quiet: bool = False, max_threads: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Scanne une liste ou une plage de ports sur une adresse IP donnée.
    
    Args:
        ip: L'adresse IP cible
        ports: Liste de ports ou range(start_port, end_port+1) à scanner
        timeout: Délai d'attente pour chaque tentative de connexion
        quiet: Si True, supprime l'affichage des résultats en temps réel
        max_threads: Nombre maximum de threads (utilise la config par défaut si None)
        
    Returns:
        List[Dict]: Liste des résultats de scan triés par numéro de port
        
    Raises:
        ValueError: Si l'IP est invalide ou si les ports sont invalides
    """
    if not validate_ip(ip):
        raise ValueError(f"Adresse IP invalide: {ip}")
        
    # Convertir la plage en liste si nécessaire pour obtenir le nombre de ports
    ports_list = list(ports) if isinstance(ports, range) else ports
    
    # Valider tous les ports
    for port in ports_list:
        if not validate_port(port):
            raise ValueError(f"Numéro de port invalide: {port}")
    
    if not quiet:
        print(f"Scanning {ip} on {len(ports_list)} ports using multi-threading...")
    
    start_time = time.time()
    
    # Initialisation des variables
    port_queue = Queue()
    results = []
    print_lock = threading.Lock()
    stop_event = threading.Event()
    
    # Remplir la queue avec les ports
    for port in ports:
        port_queue.put(port)
    
    # Déterminer le nombre de threads à utiliser
    actual_max_threads = max_threads if max_threads is not None else MAX_THREADS
    num_threads = min(len(ports_list), actual_max_threads)
    
    # Créer et démarrer les threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(
            target=_scan_common, 
            args=(ip, port_queue, results, print_lock, timeout, quiet, stop_event)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    try:
        # Attendre que tous les ports soient scannés
        port_queue.join()
    except KeyboardInterrupt:
        # Permettre l'arrêt propre du scan avec Ctrl+C
        if not quiet:
            print("\nScan interrompu par l'utilisateur")
        stop_event.set()
    
    # Attendre que tous les threads se terminent
    for thread in threads:
        thread.join(timeout=1.0)  # Timeout pour éviter le blocage indéfini
    
    elapsed_time = time.time() - start_time
    if not quiet:
        print(f"\nScan completed in {elapsed_time:.2f} seconds")
    
    return sorted(results, key=lambda x: x['port'])


def scan_specific_ports(ip: str, ports: List[int], timeout: float = 1, quiet: bool = False,  callback=None) -> List[Dict[str, Any]]:
    """
    Scanne une liste spécifique de ports sur une adresse IP donnée.
    
    Args:
        ip: L'adresse IP cible
        ports: Liste des ports spécifiques à scanner
        timeout: Délai d'attente pour chaque tentative de connexion
        quiet: Si True, supprime l'affichage des résultats en temps réel
        
    Returns:
        List[Dict]: Liste des résultats de scan triés par numéro de port
    """
    return scan_ports(ip, ports, timeout, quiet)


def scan_range(ip: str, start_port: int, end_port: int, timeout: float = 1, quiet: bool = False, callback=None) -> List[Dict[str, Any]]:
    """
    Scanne une plage de ports sur une adresse IP donnée.
    
    Args:
        ip: L'adresse IP cible
        start_port: Premier port de la plage à scanner
        end_port: Dernier port de la plage à scanner
        timeout: Délai d'attente pour chaque tentative de connexion
        quiet: Si True, supprime l'affichage des résultats en temps réel
        
    Returns:
        List[Dict]: Liste des résultats de scan triés par numéro de port
    """
    return scan_ports(ip, range(start_port, end_port + 1), timeout, quiet)


# Backward compatibility
def worker(ip, port_queue, results, print_lock, quiet=False):
    """
    Fonction maintenue pour compatibilité avec le code existant.
    Préférez utiliser _scan_common pour les nouvelles implémentations.
    """
    _scan_common(ip, port_queue, results, print_lock, timeout=1, quiet=quiet)