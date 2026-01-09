#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Détection de Failles Web Simples
Audit applicatif basique avec détection XSS, SQLi, et vérification des headers de sécurité
"""

import requests
import argparse
import sys
import re
import socket
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Tuple
import json
from datetime import datetime
import ssl
import urllib3

# Désactive les avertissements SSL (pour les tests)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Codes couleur ANSI
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'

# Payloads XSS courants
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    "javascript:alert('XSS')",
    '<body onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '<iframe src="javascript:alert(\'XSS\')">',
    '<input type="text" value="<script>alert(\'XSS\')</script>">',
    '<img src="x" onerror="alert(\'XSS\')">'
]

# Payloads SQLi courants
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' UNION SELECT NULL--",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR '1'='1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "admin' UNION SELECT 1,2,3--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--"
]

# Headers de sécurité à vérifier
SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'required': False,
        'description': 'Protection contre les attaques XSS et injection',
        'recommendation': "Implémenter CSP avec 'default-src self'"
    },
    'Strict-Transport-Security': {
        'required': True,
        'description': 'Force HTTPS (HSTS)',
        'recommendation': "Ajouter 'max-age=31536000; includeSubDomains'"
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Protection contre le clickjacking',
        'recommendation': "Définir sur 'DENY' ou 'SAMEORIGIN'"
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': "Empêche le MIME-sniffing",
        'recommendation': "Définir sur 'nosniff'"
    },
    'X-XSS-Protection': {
        'required': False,
        'description': 'Protection XSS du navigateur',
        'recommendation': "Définir sur '1; mode=block'"
    },
    'Referrer-Policy': {
        'required': False,
        'description': 'Contrôle les informations du referrer',
        'recommendation': "Définir sur 'strict-origin-when-cross-origin'"
    },
    'Permissions-Policy': {
        'required': False,
        'description': 'Contrôle les fonctionnalités du navigateur',
        'recommendation': "Restreindre les fonctionnalités non nécessaires"
    }
}

class WebVulnerabilityScanner:
    def __init__(self, target_url: str, timeout: int = 10, verify_ssl: bool = False):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = {
            'xss': [],
            'sqli': [],
            'security_headers': [],
            'forms': []
        }
        self.forms_found = []
    
    def check_ssl_configuration(self) -> Dict:
        """Vérifie la configuration SSL/TLS"""
        results = {
            'valid': False,
            'certificate_valid': False,
            'issues': []
        }
        
        try:
            parsed = urlparse(self.target_url)
            if parsed.scheme != 'https':
                results['issues'].append('Le site n\'utilise pas HTTPS')
                return results
            
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['valid'] = True
                    results['certificate_valid'] = True
                    
                    # Vérifie la version TLS
                    version = ssock.version()
                    if version == 'TLSv1':
                        results['issues'].append('TLS 1.0 est obsolète et vulnérable')
                    elif version == 'TLSv1.1':
                        results['issues'].append('TLS 1.1 est obsolète')
                    elif version in ['TLSv1.2', 'TLSv1.3']:
                        results['issues'].append(f'Version TLS sécurisée: {version}')
                    
        except Exception as e:
            results['issues'].append(f'Erreur lors de la vérification SSL: {str(e)}')
        
        return results
    
    def fetch_page(self, url: str) -> Optional[requests.Response]:
        """Récupère une page web"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Colors.YELLOW}[!] Erreur lors de la récupération de {url}: {e}{Colors.RESET}")
            return None
    
    def find_forms(self, html: str, base_url: str) -> List[Dict]:
        """Trouve tous les formulaires dans la page"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'url': base_url
            }
            
            # Trouve tous les champs d'input
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'required': input_tag.has_attr('required')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            # Complète l'URL de l'action
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
            
            forms.append(form_data)
            self.forms_found.append(form_data)
        
        return forms
    
    def test_xss_in_parameter(self, url: str, param: str, payload: str) -> bool:
        """Teste une injection XSS dans un paramètre"""
        try:
            # Construit l'URL avec le payload
            params = {param: payload}
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            # Vérifie si le payload est réfléchi dans la réponse
            if payload in response.text or payload.replace("'", "&#39;") in response.text:
                # Vérifie si le script est exécutable (pas encodé)
                if '<script>' in payload.lower() and '<script>' in response.text.lower():
                    return True
                if 'onerror=' in payload.lower() and 'onerror=' in response.text.lower():
                    return True
                if 'javascript:' in payload.lower() and 'javascript:' in response.text.lower():
                    return True
            
            return False
        except:
            return False
    
    def test_xss_in_form(self, form: Dict, payload: str) -> bool:
        """Teste une injection XSS dans un formulaire"""
        try:
            data = {}
            
            # Remplit tous les champs avec le payload
            for input_field in form['inputs']:
                if input_field['name']:
                    data[input_field['name']] = payload
            
            if not data:
                return False
            
            # Envoie le formulaire
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=data, timeout=self.timeout)
            
            # Vérifie la réflexion
            if payload in response.text or payload.replace("'", "&#39;") in response.text:
                if '<script>' in payload.lower() and '<script>' in response.text.lower():
                    return True
                if 'onerror=' in payload.lower() and 'onerror=' in response.text.lower():
                    return True
            
            return False
        except:
            return False
    
    def test_sqli_in_parameter(self, url: str, param: str, payload: str) -> bool:
        """Teste une injection SQL dans un paramètre"""
        try:
            params = {param: payload}
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            # Indicateurs d'erreur SQL
            sql_errors = [
                'sql syntax',
                'mysql_fetch',
                'mysql_num_rows',
                'mysqli_query',
                'pg_query',
                'ORA-01756',
                'Microsoft OLE DB Provider',
                'ODBC SQL Server Driver',
                'SQLServer JDBC Driver',
                'PostgreSQL query failed',
                'Warning: pg_',
                'valid MySQL result',
                'MySqlClient',
                'PostgreSQL query failed',
                'syntax error at or near'
            ]
            
            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    return True
            
            return False
        except:
            return False
    
    def test_sqli_in_form(self, form: Dict, payload: str) -> bool:
        """Teste une injection SQL dans un formulaire"""
        try:
            data = {}
            
            for input_field in form['inputs']:
                if input_field['name']:
                    data[input_field['name']] = payload
            
            if not data:
                return False
            
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=data, timeout=self.timeout)
            
            sql_errors = [
                'sql syntax',
                'mysql_fetch',
                'mysql_num_rows',
                'mysqli_query',
                'pg_query',
                'ORA-01756',
                'Microsoft OLE DB Provider',
                'ODBC SQL Server Driver'
            ]
            
            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    return True
            
            return False
        except:
            return False
    
    def check_security_headers(self, response: requests.Response) -> Dict:
        """Vérifie les headers de sécurité"""
        headers_found = {}
        headers_missing = []
        headers_issues = []
        
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name in response.headers:
                headers_found[header_name] = {
                    'value': response.headers[header_name],
                    'description': header_info['description'],
                    'required': header_info['required']
                }
                
                # Vérifie la configuration
                value = response.headers[header_name].lower()
                
                if header_name == 'Strict-Transport-Security':
                    if 'max-age' not in value:
                        headers_issues.append(f'{header_name}: max-age manquant')
                
                elif header_name == 'X-Frame-Options':
                    if value not in ['deny', 'sameorigin']:
                        headers_issues.append(f'{header_name}: valeur non sécurisée ({response.headers[header_name]})')
                
                elif header_name == 'X-Content-Type-Options':
                    if value != 'nosniff':
                        headers_issues.append(f'{header_name}: devrait être "nosniff"')
                
                elif header_name == 'Content-Security-Policy':
                    if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                        headers_issues.append(f'{header_name}: contient unsafe-inline ou unsafe-eval')
            else:
                if header_info['required']:
                    headers_missing.append({
                        'header': header_name,
                        'description': header_info['description'],
                        'recommendation': header_info['recommendation']
                    })
        
        return {
            'found': headers_found,
            'missing': headers_missing,
            'issues': headers_issues
        }
    
    def scan(self) -> Dict:
        """Lance le scan complet"""
        print(f"{Colors.CYAN}[*] Démarrage du scan de sécurité web{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Cible: {self.target_url}{Colors.RESET}\n")
        
        # Récupère la page principale
        print(f"{Colors.BLUE}[*] Récupération de la page principale...{Colors.RESET}")
        response = self.fetch_page(self.target_url)
        
        if not response:
            print(f"{Colors.RED}[!] Impossible de récupérer la page{Colors.RESET}")
            return self.vulnerabilities
        
        print(f"{Colors.GREEN}[+] Page récupérée (Status: {response.status_code}){Colors.RESET}\n")
        
        # Vérifie les headers de sécurité
        print(f"{Colors.BLUE}[*] Vérification des headers de sécurité...{Colors.RESET}")
        headers_check = self.check_security_headers(response)
        self.vulnerabilities['security_headers'] = headers_check
        
        if headers_check['missing']:
            print(f"{Colors.YELLOW}[!] {len(headers_check['missing'])} headers de sécurité manquants{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[+] Tous les headers requis sont présents{Colors.RESET}")
        
        if headers_check['issues']:
            print(f"{Colors.YELLOW}[!] {len(headers_check['issues'])} problèmes de configuration détectés{Colors.RESET}")
        
        print()
        
        # Trouve les formulaires
        print(f"{Colors.BLUE}[*] Recherche de formulaires...{Colors.RESET}")
        forms = self.find_forms(response.text, self.target_url)
        print(f"{Colors.GREEN}[+] {len(forms)} formulaire(s) trouvé(s){Colors.RESET}\n")
        
        # Teste les formulaires pour XSS et SQLi
        if forms:
            print(f"{Colors.BLUE}[*] Test des formulaires pour XSS et SQLi...{Colors.RESET}")
            for i, form in enumerate(forms, 1):
                print(f"  Formulaire {i}/{len(forms)}: {form['action']} ({form['method']})")
                
                # Test XSS
                for payload in XSS_PAYLOADS[:3]:  # Teste les 3 premiers payloads
                    if self.test_xss_in_form(form, payload):
                        self.vulnerabilities['xss'].append({
                            'type': 'formulaire',
                            'url': form['action'],
                            'payload': payload,
                            'severity': 'high'
                        })
                        print(f"    {Colors.RED}[!] XSS potentiel détecté{Colors.RESET}")
                        break
                
                # Test SQLi
                for payload in SQLI_PAYLOADS[:5]:  # Teste les 5 premiers payloads
                    if self.test_sqli_in_form(form, payload):
                        self.vulnerabilities['sqli'].append({
                            'type': 'formulaire',
                            'url': form['action'],
                            'payload': payload,
                            'severity': 'critical'
                        })
                        print(f"    {Colors.RED}[!] SQLi potentiel détecté{Colors.RESET}")
                        break
            
            print()
        
        # Analyse les paramètres URL
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            print(f"{Colors.BLUE}[*] Test des paramètres URL pour XSS et SQLi...{Colors.RESET}")
            params = parse_qs(parsed_url.query)
            
            for param in params.keys():
                # Test XSS
                for payload in XSS_PAYLOADS[:2]:
                    if self.test_xss_in_parameter(self.target_url, param, payload):
                        self.vulnerabilities['xss'].append({
                            'type': 'paramètre_url',
                            'parameter': param,
                            'payload': payload,
                            'severity': 'high'
                        })
                        print(f"  {Colors.RED}[!] XSS potentiel dans paramètre: {param}{Colors.RESET}")
                        break
                
                # Test SQLi
                for payload in SQLI_PAYLOADS[:3]:
                    if self.test_sqli_in_parameter(self.target_url, param, payload):
                        self.vulnerabilities['sqli'].append({
                            'type': 'paramètre_url',
                            'parameter': param,
                            'payload': payload,
                            'severity': 'critical'
                        })
                        print(f"  {Colors.RED}[!] SQLi potentiel dans paramètre: {param}{Colors.RESET}")
                        break
            
            print()
        
        # Résumé
        total_vulns = (len(self.vulnerabilities['xss']) + 
                      len(self.vulnerabilities['sqli']) + 
                      len(headers_check['missing']))
        
        print(f"{Colors.CYAN}[*] Scan terminé{Colors.RESET}\n")
        
        return self.vulnerabilities

class ReportGenerator:
    def __init__(self, target_url: str, vulnerabilities: Dict, output_dir: str = 'reports'):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def generate_txt_report(self) -> str:
        """Génère un rapport texte"""
        filename = os.path.join(self.output_dir, f'rapport_failles_{urlparse(self.target_url).netloc.replace(":", "_")}_{self.timestamp}.txt')
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"RAPPORT D'AUDIT WEB - {self.target_url}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Cible: {self.target_url}\n\n")
            
            # XSS
            f.write("-" * 80 + "\n")
            f.write("VULNÉRABILITÉS XSS\n")
            f.write("-" * 80 + "\n\n")
            xss_vulns = self.vulnerabilities.get('xss', [])
            if xss_vulns:
                for i, vuln in enumerate(xss_vulns, 1):
                    f.write(f"{i}. Type: {vuln['type']}\n")
                    f.write(f"   URL/Paramètre: {vuln.get('url', vuln.get('parameter', 'N/A'))}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Sévérité: {vuln['severity']}\n\n")
            else:
                f.write("Aucune vulnérabilité XSS détectée.\n\n")
            
            # SQLi
            f.write("-" * 80 + "\n")
            f.write("VULNÉRABILITÉS SQL INJECTION\n")
            f.write("-" * 80 + "\n\n")
            sqli_vulns = self.vulnerabilities.get('sqli', [])
            if sqli_vulns:
                for i, vuln in enumerate(sqli_vulns, 1):
                    f.write(f"{i}. Type: {vuln['type']}\n")
                    f.write(f"   URL/Paramètre: {vuln.get('url', vuln.get('parameter', 'N/A'))}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Sévérité: {vuln['severity']}\n\n")
            else:
                f.write("Aucune vulnérabilité SQL Injection détectée.\n\n")
            
            # Headers de sécurité
            f.write("-" * 80 + "\n")
            f.write("HEADERS DE SÉCURITÉ\n")
            f.write("-" * 80 + "\n\n")
            headers_check = self.vulnerabilities.get('security_headers', {})
            
            if headers_check.get('found'):
                f.write("Headers présents:\n")
                for header, info in headers_check['found'].items():
                    f.write(f"  {header}: {info['value']}\n")
                f.write("\n")
            
            if headers_check.get('missing'):
                f.write("Headers manquants (RECOMMANDÉS):\n")
                for header_info in headers_check['missing']:
                    f.write(f"  - {header_info['header']}\n")
                    f.write(f"    Description: {header_info['description']}\n")
                    f.write(f"    Recommandation: {header_info['recommendation']}\n\n")
            
            if headers_check.get('issues'):
                f.write("Problèmes de configuration:\n")
                for issue in headers_check['issues']:
                    f.write(f"  - {issue}\n")
                f.write("\n")
            
            # Recommandations
            f.write("=" * 80 + "\n")
            f.write("RECOMMANDATIONS\n")
            f.write("=" * 80 + "\n\n")
            
            if xss_vulns:
                f.write("1. Protéger contre XSS:\n")
                f.write("   - Valider et échapper toutes les entrées utilisateur\n")
                f.write("   - Utiliser Content-Security-Policy (CSP)\n")
                f.write("   - Encoder les sorties HTML\n\n")
            
            if sqli_vulns:
                f.write("2. Protéger contre SQL Injection:\n")
                f.write("   - Utiliser des requêtes préparées (prepared statements)\n")
                f.write("   - Valider toutes les entrées\n")
                f.write("   - Utiliser un ORM avec protection intégrée\n")
                f.write("   - Appliquer le principe du moindre privilège pour les bases de données\n\n")
            
            if headers_check.get('missing'):
                f.write("3. Implémenter les headers de sécurité manquants\n")
                f.write("   - Configuration du serveur web (Apache/Nginx)\n")
                f.write("   - Ou configuration au niveau de l'application\n\n")
            
            f.write("=" * 80 + "\n")
        
        return filename
    
    def generate_json_report(self) -> str:
        """Génère un rapport JSON"""
        filename = os.path.join(self.output_dir, f'rapport_failles_{urlparse(self.target_url).netloc.replace(":", "_")}_{self.timestamp}.json')
        
        report = {
            'metadata': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'report_version': '1.0'
            },
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'xss_count': len(self.vulnerabilities.get('xss', [])),
                'sqli_count': len(self.vulnerabilities.get('sqli', [])),
                'missing_headers_count': len(self.vulnerabilities.get('security_headers', {}).get('missing', [])),
                'total_issues': (len(self.vulnerabilities.get('xss', [])) + 
                               len(self.vulnerabilities.get('sqli', [])) + 
                               len(self.vulnerabilities.get('security_headers', {}).get('missing', [])))
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename

def main():
    parser = argparse.ArgumentParser(
        description='Détection de Failles Web Simples',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python detection_failles.py https://example.com
  python detection_failles.py http://testphp.vulnweb.com --verify-ssl
  python detection_failles.py https://example.com --json-only
  python detection_failles.py http://192.168.1.1 --output-dir results
        """
    )
    
    parser.add_argument('url', help='URL cible à scanner')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout en secondes (défaut: 10)')
    parser.add_argument('--verify-ssl', action='store_true', help='Vérifier les certificats SSL')
    parser.add_argument('--output-dir', '-o', default='reports', help='Répertoire de sortie (défaut: reports)')
    parser.add_argument('--json-only', action='store_true', help='Générer uniquement le rapport JSON')
    parser.add_argument('--txt-only', action='store_true', help='Générer uniquement le rapport TXT')
    
    args = parser.parse_args()
    
    # Valide l'URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.YELLOW}[!] Avertissement: L'URL ne commence pas par http:// ou https://{Colors.RESET}")
        args.url = 'http://' + args.url
        print(f"{Colors.CYAN}[*] Utilisation de: {args.url}{Colors.RESET}\n")
    
    # Lance le scan
    scanner = WebVulnerabilityScanner(args.url, args.timeout, args.verify_ssl)
    vulnerabilities = scanner.scan()
    
    # Génère les rapports
    report_gen = ReportGenerator(args.url, vulnerabilities, args.output_dir)
    
    # Affiche le résumé
    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}RÉSUMÉ{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")
    
    xss_count = len(vulnerabilities.get('xss', []))
    sqli_count = len(vulnerabilities.get('sqli', []))
    missing_headers = len(vulnerabilities.get('security_headers', {}).get('missing', []))
    
    if xss_count > 0:
        print(f"{Colors.RED}[!] XSS: {xss_count} vulnérabilité(s) détectée(s){Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] XSS: Aucune vulnérabilité détectée{Colors.RESET}")
    
    if sqli_count > 0:
        print(f"{Colors.RED}[!] SQL Injection: {sqli_count} vulnérabilité(s) détectée(s){Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] SQL Injection: Aucune vulnérabilité détectée{Colors.RESET}")
    
    if missing_headers > 0:
        print(f"{Colors.YELLOW}[!] Headers de sécurité: {missing_headers} header(s) manquant(s){Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] Headers de sécurité: Tous les headers requis sont présents{Colors.RESET}")
    
    print()
    
    # Génère les fichiers
    if not args.json_only:
        txt_file = report_gen.generate_txt_report()
        print(f"{Colors.GREEN}[+] Rapport TXT généré: {txt_file}{Colors.RESET}")
    
    if not args.txt_only:
        json_file = report_gen.generate_json_report()
        print(f"{Colors.GREEN}[+] Rapport JSON généré: {json_file}{Colors.RESET}")
    
    print()

if __name__ == '__main__':
    main()

