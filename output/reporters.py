import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

# Constants for HTML styling and scripts
HTML_CSS = """
    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
    h1, h2, h3 { color: #444; }
    .container { max-width: 1200px; margin: 0 auto; }
    .summary { background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    .port-details { border: 1px solid #ddd; margin-bottom: 15px; border-radius: 5px; overflow: hidden; }
    .port-header { background-color: #eee; padding: 10px 15px; cursor: pointer; }
    .port-header.vulnerable { background-color: #ffdddd; }
    .port-content { padding: 15px; display: none; }
    .vuln { background-color: #fff0f0; padding: 10px; margin-top: 10px; border-left: 4px solid #ff6b6b; }
    .high { border-left-color: #ff0000; }
    .medium { border-left-color: #ff9900; }
    .low { border-left-color: #ffcc00; }
    pre { background-color: #f8f8f8; padding: 10px; border-radius: 3px; overflow-x: auto; }
    .toggle-btn { background: none; border: none; color: #0066cc; cursor: pointer; }
    .timestamp { color: #666; font-size: 0.9em; }
    .export-links { margin-top: 20px; padding: 10px; background-color: #f0f0f0; border-radius: 5px; }
    .export-links a { margin-right: 15px; }
"""

HTML_SCRIPT = """
    function toggleDetails(element) {
        var content = element.nextElementSibling;
        if (content.style.display === "block") {
            content.style.display = "none";
        } else {
            content.style.display = "block";
        }
    }
    
    // Ouvrir automatiquement les ports vulnérables
    document.addEventListener('DOMContentLoaded', function() {
        var vulnHeaders = document.querySelectorAll('.port-header.vulnerable');
        vulnHeaders.forEach(function(header) {
            header.nextElementSibling.style.display = "block";
        });
    });
    
    function toggleAllPorts(show) {
        var portContents = document.querySelectorAll('.port-content');
        portContents.forEach(function(content) {
            content.style.display = show ? "block" : "none";
        });
    }
"""

def generate_filename(ip: str, extension: str, custom_name: Optional[str] = None) -> str:
    """
    Génère un nom de fichier standardisé pour les rapports.
    
    Args:
        ip: Adresse IP cible du scan
        extension: Extension du fichier (sans le point)
        custom_name: Nom personnalisé optionnel
        
    Returns:
        Le nom de fichier généré
    """
    if custom_name:
        if not custom_name.endswith(f".{extension}"):
            return f"{custom_name}.{extension}"
        return custom_name
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{ip.replace('.', '_')}_{timestamp}.{extension}"

def count_vulnerabilities(results: List[Dict[str, Any]]) -> int:
    """
    Compte le nombre total de vulnérabilités dans les résultats.
    
    Args:
        results: Liste des résultats de scan par port
        
    Returns:
        Nombre total de vulnérabilités
    """
    return sum(len(r.get('vulnerabilities', [])) for r in results)

def save_to_html(ip: str, results: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    Enregistre les résultats dans un fichier HTML interactif.
    
    Le rapport HTML généré inclut une présentation interactive des ports ouverts,
    des vulnérabilités détectées avec leur niveau de gravité, et permet de visualiser
    facilement les informations de bannière.
    
    Args:
        ip: Adresse IP cible du scan
        results: Liste des résultats de scan par port
        filename: Nom du fichier de sortie (optionnel)
        
    Returns:
        Le chemin du fichier enregistré
        
    Raises:
        IOError: Si l'écriture du fichier échoue
    """
    if not filename:
        filename = generate_filename(ip, "html")
    
    vuln_count = count_vulnerabilities(results)
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Construction du HTML
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report - {ip}</title>
    <style>{HTML_CSS}</style>
</head>
<body>
    <div class="container">
        <h1>Network Scan Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target IP:</strong> {ip}</p>
            <p><strong>Scan Date:</strong> <span class="timestamp">{scan_date}</span></p>
            <p><strong>Open Ports:</strong> {len(results)}</p>
            <p><strong>Vulnerabilities Found:</strong> {vuln_count}</p>
            
            <div class="controls">
                <button onclick="toggleAllPorts(true)">Expand All</button>
                <button onclick="toggleAllPorts(false)">Collapse All</button>
            </div>
        </div>
"""
    
    # Ajouter les détails pour chaque port
    if results:
        html += "<h2>Detailed Results</h2>\n"
        
        for result in results:
            port = result['port']
            service = result['service']
            banner = result.get('banner', '')
            vulnerabilities = result.get('vulnerabilities', [])
            
            # Déterminer si le port a des vulnérabilités
            has_vulns = len(vulnerabilities) > 0
            vuln_class = "vulnerable" if has_vulns else ""
            
            html += f"""
        <div class="port-details">
            <div class="port-header {vuln_class}" onclick="toggleDetails(this)">
                <h3>Port {port} - {service} {' (Vulnerable)' if has_vulns else ''}</h3>
            </div>
            <div class="port-content">
"""
            
            if banner:
                # Sécuriser la bannière pour l'affichage HTML
                safe_banner = banner.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += f"<p><strong>Banner:</strong></p>\n<pre>{safe_banner}</pre>\n"
            
            if vulnerabilities:
                html += f"<h4>Vulnerabilities ({len(vulnerabilities)})</h4>\n"
                
                for vuln in vulnerabilities:
                    v_type = vuln['type']
                    severity = vuln.get('severity', 'Unknown').lower()
                    description = vuln.get('description', 'No description available')
                    
                    html += f"""
                <div class="vuln {severity}">
                    <h5>{v_type} [Severity: {vuln.get('severity', 'Unknown')}]</h5>
                    <p>{description}</p>
"""
                    
                    # Ajouter des détails spécifiques selon le type de vulnérabilité
                    for detail_type, items in [
                        ('missing_headers', 'Missing Headers'), 
                        ('issues', 'Issues'),
                        ('directories', 'Accessible Directories')
                    ]:
                        if detail_type in vuln and vuln[detail_type]:
                            html += f"<p><strong>{items}:</strong></p>\n<ul>\n"
                            for item in vuln[detail_type]:
                                html += f"<li>{item}</li>\n"
                            html += "</ul>\n"
                    
                    html += "</div>\n"
            
            html += "</div>\n</div>\n"
    else:
        html += "<p>No open ports found.</p>\n"
    
    # Ajouter des liens d'export
    html += f"""
        <div class="export-links">
            <h3>Export Results</h3>
            <a href="{os.path.splitext(filename)[0]}.txt" target="_blank">Export as TXT</a>
            <a href="{os.path.splitext(filename)[0]}.json" target="_blank">Export as JSON</a>
            <a href="{os.path.splitext(filename)[0]}.csv" target="_blank">Export as CSV</a>
        </div>
        <script>{HTML_SCRIPT}</script>
    </div>
</body>
</html>
"""
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"Results saved to HTML file: {filename}")
        return filename
    except IOError as e:
        print(f"Error saving HTML file: {e}")
        raise

def save_to_txt(ip: str, results: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    Enregistre les résultats dans un fichier texte.
    
    Génère un rapport texte brut avec l'ensemble des informations de scan,
    incluant les détails sur les ports ouverts et les vulnérabilités.
    
    Args:
        ip: Adresse IP cible du scan
        results: Liste des résultats de scan par port
        filename: Nom du fichier de sortie (optionnel)
        
    Returns:
        Le chemin du fichier enregistré
        
    Raises:
        IOError: Si l'écriture du fichier échoue
    """
    if not filename:
        filename = generate_filename(ip, "txt")
    
    vuln_count = count_vulnerabilities(results)
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Network Scanner Results\n")
            f.write(f"=====================\n\n")
            f.write(f"Target IP: {ip}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open Ports: {len(results)}\n")
            f.write(f"Vulnerabilities Found: {vuln_count}\n\n")
            
            if results:
                f.write("DETAILED RESULTS\n")
                f.write("===============\n\n")
                
                for result in results:
                    port = result['port']
                    service = result['service']
                    banner = result.get('banner', '')
                    vulnerabilities = result.get('vulnerabilities', [])
                    
                    f.write(f"Port {port} - {service}\n")
                    if banner:
                        f.write(f"  Banner: {banner}\n")
                    
                    if vulnerabilities:
                        f.write(f"  VULNERABILITIES ({len(vulnerabilities)}):\n")
                        for vuln in vulnerabilities:
                            f.write(f"    - {vuln['type']} [Severity: {vuln.get('severity', 'Unknown')}]\n")
                            f.write(f"      {vuln.get('description', 'No description available')}\n")
                            
                            # Ajouter des détails spécifiques selon le type de vulnérabilité
                            for detail_type, label in [
                                ('missing_headers', 'Missing headers'),
                                ('issues', 'Issues'),
                                ('directories', 'Accessible directories')
                            ]:
                                if detail_type in vuln and vuln[detail_type]:
                                    f.write(f"      {label}:\n")
                                    for item in vuln[detail_type]:
                                        f.write(f"        * {item}\n")
                    
                    f.write("\n")
            else:
                f.write("No open ports found.\n")
        
        print(f"Results saved to text file: {filename}")
        return filename
    except IOError as e:
        print(f"Error saving text file: {e}")
        raise

def save_to_json(ip: str, results: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    Enregistre les résultats dans un fichier JSON.
    
    Sauvegarde toutes les données du scan dans un format structuré facile à traiter
    par d'autres applications ou scripts.
    
    Args:
        ip: Adresse IP cible du scan
        results: Liste des résultats de scan par port
        filename: Nom du fichier de sortie (optionnel)
        
    Returns:
        Le chemin du fichier enregistré
        
    Raises:
        IOError: Si l'écriture du fichier échoue
    """
    if not filename:
        filename = generate_filename(ip, "json")
    
    vuln_count = count_vulnerabilities(results)
    
    # Préparer les données pour le JSON
    data = {
        "target_ip": ip,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports_count": len(results),
        "vulnerabilities_count": vuln_count,
        "open_ports": results
    }
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        
        print(f"Results saved to JSON file: {filename}")
        return filename
    except IOError as e:
        print(f"Error saving JSON file: {e}")
        raise

def save_to_csv(ip: str, results: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    Enregistre les résultats dans un fichier CSV.
    
    Crée un fichier CSV avec les informations essentielles du scan,
    adapté pour l'importation dans des tableurs ou d'autres outils d'analyse.
    
    Args:
        ip: Adresse IP cible du scan
        results: Liste des résultats de scan par port
        filename: Nom du fichier de sortie (optionnel)
        
    Returns:
        Le chemin du fichier enregistré
        
    Raises:
        IOError: Si l'écriture du fichier échoue
    """
    if not filename:
        filename = generate_filename(ip, "csv")
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Définir les champs d'en-tête
            fieldnames = ['IP', 'Port', 'Service', 'Vulnerability', 'Severity', 'Description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            if not results:
                writer.writerow({
                    'IP': ip,
                    'Port': 'N/A',
                    'Service': 'N/A',
                    'Vulnerability': 'N/A',
                    'Severity': 'N/A',
                    'Description': 'No open ports found'
                })
            else:
                for result in results:
                    port = result['port']
                    service = result['service']
                    vulnerabilities = result.get('vulnerabilities', [])
                    
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            writer.writerow({
                                'IP': ip,
                                'Port': port,
                                'Service': service,
                                'Vulnerability': vuln['type'],
                                'Severity': vuln.get('severity', 'Unknown'),
                                'Description': vuln.get('description', 'No description available')
                            })
                    else:
                        writer.writerow({
                            'IP': ip,
                            'Port': port,
                            'Service': service,
                            'Vulnerability': 'None',
                            'Severity': 'N/A',
                            'Description': 'No vulnerabilities detected'
                        })
        
        print(f"Results saved to CSV file: {filename}")
        return filename
    except IOError as e:
        print(f"Error saving CSV file: {e}")
        raise

def save_report(ip: str, results: List[Dict[str, Any]], formats: List[str] = ['html'], filename_base: Optional[str] = None) -> Dict[str, str]:
    """
    Fonction combinée pour enregistrer les résultats dans plusieurs formats.
    
    Args:
        ip: Adresse IP cible du scan
        results: Liste des résultats de scan par port
        formats: Liste des formats souhaités ('html', 'txt', 'json', 'csv')
        filename_base: Base du nom de fichier sans extension (optionnel)
        
    Returns:
        Dictionnaire avec les chemins des fichiers générés par format
    """
    output_files = {}
    
    format_handlers = {
        'html': save_to_html,
        'txt': save_to_txt,
        'json': save_to_json,
        'csv': save_to_csv
    }
    
    for fmt in formats:
        if fmt.lower() in format_handlers:
            filename = None if not filename_base else f"{filename_base}.{fmt.lower()}"
            try:
                output_files[fmt] = format_handlers[fmt.lower()](ip, results, filename)
            except Exception as e:
                print(f"Error generating {fmt} report: {e}")
        else:
            print(f"Unsupported format: {fmt}")
    
    return output_files