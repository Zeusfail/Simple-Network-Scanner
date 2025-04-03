import argparse
import os
import sys
from datetime import datetime
from utils.config import *
from core.stealth_scanner import *
from core.port_scanner import *
from output.reporters import *

# Importation de rich pour améliorer l'affichage console
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich import print as rprint
from rich.text import Text

# Créer une instance console
console = Console()

def clear_console():
    """Clear the console screen based on the OS platform."""
    if sys.platform == "win32":
        os.system('cls')
    else:
        os.system('clear')

def main():
    # Clear the console at startup
    clear_console()

    # Utiliser argparse pour gérer les arguments en ligne de commande
    parser = argparse.ArgumentParser(
        description='Network Port Scanner with Service Detection and Vulnerability Checks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Arguments principaux
    parser.add_argument('-t', '--target', dest='ip', required=True,
                        help='Target IP address or hostname')
    
    # Options pour la plage de ports
    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument('-p', '--ports', dest='port_range',
                          help='Port range to scan (e.g., 1-1000 or 80,443,8080)')
    port_group.add_argument('--top-ports', dest='top_ports', type=int, choices=[10, 20, 50, 100],
                          help='Scan N most common ports')
    
    # Options de scan
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-T', '--threads', type=int, default=MAX_THREADS,
                          help=f'Number of threads to use (max: {MAX_THREADS})')
    scan_group.add_argument('--timeout', type=float, default=1.0,
                          help='Timeout in seconds for port connection attempts')
    scan_group.add_argument('--no-banner', action='store_true',
                          help='Skip banner grabbing (faster scan)')
    scan_group.add_argument('--no-vuln-check', action='store_true',
                          help='Disable vulnerability checks (faster scan)')
    scan_group.add_argument('-s', '--stealth', action='store_true',
                          help='Use stealth SYN scan (requires root/admin privileges)')
    
    # Options de sortie
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--txt', action='store_true',
                            help='Save results to a TXT file')
    output_group.add_argument('--json', action='store_true',
                            help='Save results to a JSON file')
    output_group.add_argument('--html', action='store_true',
                            help='Save results to an HTML report')
    output_group.add_argument('-o', '--output', default='',
                            help='Output directory for saved files')
    output_group.add_argument('-q', '--quiet', action='store_true',
                            help='Suppress scan details, only show summary')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Show more detailed output')
    
    args = parser.parse_args()
    
    # Traitement de l'adresse IP/hostname
    ip = args.ip
    
    # Traitement de la plage de ports
    if args.port_range:
        # Traitement des formats comme "1-1000" ou "80,443,8080"
        ports = []
        segments = args.port_range.split(',')
        
        for segment in segments:
            if '-' in segment:
                # Format plage (ex: 1-1000)
                start, end = map(int, segment.split('-'))
                ports.extend(range(start, end + 1))
            else:
                # Format port unique (ex: 80)
                ports.append(int(segment))
        
        # Éliminer les doublons et trier
        ports = sorted(set(ports))
        
        # Vérifier les limites
        if not all(1 <= p <= 65535 for p in ports):
            console.print("[bold red]Error:[/bold red] All ports must be in range 1-65535")
            sys.exit(1)
        
        start_port = ports[0]
        end_port = ports[-1]
    else:
        # Utilisation des ports les plus communs
        top_ports_dict = {
            10: [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389],
            20: [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888],
            50: [21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 135, 139, 143, 179, 199, 443, 445, 465, 514, 515, 
                 548, 554, 587, 646, 993, 995, 1025, 1026, 1027, 1433, 1720, 1723, 2000, 2001, 3306, 3389, 5060, 
                 5666, 5900, 6001, 8000, 8080, 8443, 8888, 10000, 32768, 49152, 49154],
            100: [20, 21, 22, 23, 25, 26, 53, 80, 81, 88, 110, 111, 113, 135, 139, 143, 179, 199, 389, 443, 445, 465, 
                  514, 515, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
                  1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
                  5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
                  8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157, 50000],
        }
        
        ports = top_ports_dict[args.top_ports]
        start_port = min(ports)
        end_port = max(ports)
    
    # Créer le répertoire de sortie s'il n'existe pas
    if args.output and not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Désactivation automatique des fonctionnalités en mode furtif
    if args.stealth:
        # En mode furtif, on ne peut pas récupérer de bannières ou faire des tests de vulnérabilité
        args.no_banner = True
        args.no_vuln_check = True
        if not args.quiet:
            console.print("[yellow]Stealth mode activated[/yellow] - Banner grabbing and vulnerability checks automatically disabled")
            
        # Vérifier si scapy est disponible
        if not SCAPY_AVAILABLE:
            console.print("[bold red]Error:[/bold red] Stealth mode requires the scapy library. Install it with: [green]pip install scapy[/green]")
            sys.exit(1)

         # Vérifier les privilèges administrateur
        if not is_admin():
            if sys.platform == "win32":
                console.print("[bold red]Error:[/bold red] Stealth scan on Windows requires administrator privileges.")
                console.print("Please run the Command Prompt as Administrator and try again.")
            else:
                console.print("[bold red]Error:[/bold red] Stealth scan on Unix/Linux requires root privileges.")
                console.print("Please use sudo to run the script with root privileges.")
            sys.exit(1)

        if sys.platform == "win32":
            try:
                from scapy.arch.windows import _check_pkt_driver_deps
                _check_pkt_driver_deps()
            except:
                console.print("[bold yellow]Warning:[/bold yellow] WinPcap/Npcap might not be properly installed.")
                console.print("Scapy requires WinPcap or Npcap for packet manipulation on Windows.")
                console.print("Please install from: [blue]https://npcap.com/[/blue]")
        
        # Vérifier les privilèges sur Unix/Linux
        if os.name == 'posix' and os.geteuid() != 0:
            console.print("[bold red]Warning:[/bold red] Stealth scan on Unix/Linux requires root privileges. Run with sudo.")
            sys.exit(1)
    
    # Modifier les paramètres de scan basés sur les options
    if args.no_banner:
        # Remplacer la fonction get_service_banner pour retourner None
        global get_service_banner
        def no_banner(*args, **kwargs):
            return None
        get_service_banner = no_banner
        if not args.quiet and not args.stealth:
            console.print("[yellow]Banner grabbing disabled[/yellow]")
    
    # Modifier les tests de vulnérabilités si désactivés
    if args.no_vuln_check:
        global check_vulnerabilities
        def no_vuln_check(*args, **kwargs):
            return []
        check_vulnerabilities = no_vuln_check
        if not args.quiet and not args.stealth:
            console.print("[yellow]Vulnerability checks disabled[/yellow]")
    
    # Afficher les informations de scan si pas en mode silencieux
    if not args.quiet:
        scan_info = Text()
        if args.port_range:
            if len(ports) <= 10:
                scan_info.append(f"Scanning ", style="bold cyan")
                scan_info.append(f"{ip}", style="bold green")
                scan_info.append(f" on ports: ", style="bold cyan")
                scan_info.append(f"{', '.join(map(str, ports))}", style="bold white")
            else:
                scan_info.append(f"Scanning ", style="bold cyan")
                scan_info.append(f"{ip}", style="bold green")
                scan_info.append(f" on {len(ports)} ports from ", style="bold cyan")
                scan_info.append(f"{start_port}", style="bold white")
                scan_info.append(f" to ", style="bold cyan")
                scan_info.append(f"{end_port}", style="bold white")
        else:
            scan_info.append(f"Scanning ", style="bold cyan")
            scan_info.append(f"{ip}", style="bold green")
            scan_info.append(f" on top ", style="bold cyan")
            scan_info.append(f"{args.top_ports}", style="bold white")
            scan_info.append(f" common ports", style="bold cyan")
        
        console.print(Panel(scan_info, title="[bold blue]Scan Information[/bold blue]", border_style="blue"))
    
    # Réaliser le scan avec barre de progression
    if not args.quiet:
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            console=console
        ) as progress:
            # Titre de la tâche de progression
            scan_task = progress.add_task("[bold cyan]Scanning ports...", total=len(ports))
            
            # Fonction de rappel pour mettre à jour la progression
            def update_progress(port=None, total=None):
                if port is not None and total is not None:
                    # Mettre à jour la progression
                    progress.update(scan_task, completed=port)
            
            # Réaliser le scan
            if args.stealth:
                # Utiliser le scan SYN furtif
                results = stealth_scan_range(ip, start_port, end_port, timeout=args.timeout, 
                                            quiet=args.quiet, callback=update_progress)
            elif args.port_range:
                # Scan traditionnel par plage
                results = scan_range(ip, start_port, end_port, timeout=args.timeout, 
                                    quiet=args.quiet, callback=update_progress)
            else:
                # Scan des ports spécifiques
                results = scan_specific_ports(ip, ports, timeout=args.timeout, 
                                            quiet=args.quiet, callback=update_progress)
    else:
        # Scan sans affichage de progression
        if args.stealth:
            results = stealth_scan_range(ip, start_port, end_port, timeout=args.timeout, quiet=args.quiet)
        elif args.port_range:
            results = scan_range(ip, start_port, end_port, timeout=args.timeout, quiet=args.quiet)
        else:
            results = scan_specific_ports(ip, ports, timeout=args.timeout, quiet=args.quiet)
    
    # Calculer le nombre total de vulnérabilités
    vuln_count = sum(len(r.get('vulnerabilities', [])) for r in results)
    
    # Afficher les résultats
    if results:
        if not args.quiet:
            # Créer un tableau pour les résultats
            table = Table(title=f"Scan Results for {ip}", show_header=True, header_style="bold cyan")
            table.add_column("Port", style="dim")
            table.add_column("Service", style="green")
            table.add_column("Banner", style="yellow", overflow="fold")
            table.add_column("Vulnerabilities", style="red")
            
            # Ajouter les résultats au tableau
            for result in results:
                port = result['port']
                service = result['service']
                banner = result['banner']
                vulnerabilities = result.get('vulnerabilities', [])
                
                # Formater l'affichage de la bannière
                banner_display = ""
                if banner and (args.verbose or len(banner) < 100):
                    banner_lines = banner.split('\n')
                    if len(banner_lines) > 3 and not args.verbose:
                        banner_display = '\n'.join(banner_lines[:3]) + "\n..."
                    else:
                        banner_display = banner
                elif banner:
                    banner_display = f"{banner[:100]}... (use -v for full display)"
                
                # Formater l'affichage des vulnérabilités
                vuln_display = ""
                if vulnerabilities:
                    vuln_items = []
                    for vuln in vulnerabilities:
                        severity_color = {
                            "LOW": "green",
                            "MEDIUM": "yellow",
                            "HIGH": "red",
                            "CRITICAL": "bold red"
                        }.get(vuln['severity'], "white")
                        
                        vuln_text = f"{vuln['type']} ([{severity_color}]{vuln['severity']}[/{severity_color}])"
                        if args.verbose:
                            vuln_text += f"\n  {vuln['description']}"
                        vuln_items.append(vuln_text)
                    
                    vuln_display = "\n".join(vuln_items)
                
                table.add_row(str(port), service, banner_display, vuln_display or "None")
            
            console.print(table)
        
        # Afficher le résumé
        summary_table = Table(title="Scan Summary", show_header=False, border_style="cyan")
        summary_table.add_column("Item", style="bold cyan")
        summary_table.add_column("Value", style="bold white")
        
        summary_table.add_row("Target", ip)
        summary_table.add_row("Open Ports", str(len(results)))
        if vuln_count > 0:
            summary_table.add_row("Vulnerabilities", f"[bold red]{vuln_count}[/bold red]")
        else:
            summary_table.add_row("Vulnerabilities", "0")
        
        console.print(summary_table)
    else:
        console.print(Panel("[bold yellow]No open ports found in the specified range[/bold yellow]", 
                           border_style="yellow"))
    
    # Enregistrer les résultats si demandé
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_type = "stealth" if args.stealth else "standard"
    base_filename = f"scan_{scan_type}_{ip.replace('.', '_')}_{timestamp}"
    
    if args.txt:
        txt_filename = os.path.join(args.output, f"{base_filename}.txt")
        save_to_txt(ip, results, txt_filename)
        console.print(f"Results saved to: [blue]{txt_filename}[/blue]")
    
    if args.json:
        json_filename = os.path.join(args.output, f"{base_filename}.json")
        save_to_json(ip, results, json_filename)
        console.print(f"Results saved to: [blue]{json_filename}[/blue]")
    
    if args.html:
        html_filename = os.path.join(args.output, f"{base_filename}.html")
        save_to_html(ip, results, html_filename) # type: ignore
        console.print(f"Results saved to: [blue]{html_filename}[/blue]")
    
if __name__ == "__main__":
    main()