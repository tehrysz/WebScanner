import sys
import requests
import socket
import concurrent.futures
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Configuração de cores
init()
class Colors:
    RED = Fore.LIGHTRED_EX
    GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    BLUE = Fore.LIGHTBLUE_EX
    CYAN = Fore.LIGHTCYAN_EX
    WHITE = Fore.LIGHTWHITE_EX
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class TehryWebScanner:
    def __init__(self):
        self.banner = f"""
{Colors.YELLOW}████████╗███████╗██╗  ██╗██████╗ ██╗   ██╗
{Colors.YELLOW}╚══██╔══╝██╔════╝██║  ██║██╔══██╗╚██╗ ██╔╝
{Colors.YELLOW}   ██║   █████╗  ███████║██████╔╝ ╚████╔╝ 
{Colors.YELLOW}   ██║   ██╔══╝  ██╔══██║██╔══██╗  ╚██╔╝  
{Colors.YELLOW}   ██║   ███████╗██║  ██║██║  ██║   ██║   
{Colors.YELLOW}   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝{Colors.RESET}

{Colors.CYAN}╔══════════════════════════════════════════╗
{Colors.CYAN}║      TEHRY WEB VULNERABILITY SCANNER     ║
{Colors.CYAN}║           © 2025 TEHRY SECURITY          ║
{Colors.CYAN}╚══════════════════════════════════════════╝{Colors.RESET}
"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TEHRY-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

    def show_banner(self):
        print(self.banner)

    def check_sql_injection(self, url):
        """Detecta possíveis vulnerabilidades SQL Injection"""
        print(f"\n{Colors.BLUE}[🔍] {Colors.WHITE}Testing for SQL Injection...")
        
        test_params = {
            'id': "1'",
            'search': "' OR '1'='1",
            'user': "admin'--"
        }
        
        vulnerable = False
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test GET parameters
            if parsed.query:
                for param in parsed.query.split('&'):
                    key = param.split('=')[0]
                    for payload in test_params.values():
                        test_url = f"{base_url}?{key}={payload}"
                        response = self.session.get(test_url, timeout=5)
                        
                        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'oracle']):
                            print(f"{Colors.RED}[!] Possible SQLi at: {Colors.WHITE}{test_url}")
                            vulnerable = True
            
            # Test POST if login form exists
            if '<form' in self.session.get(url).text.lower():
                print(f"{Colors.BLUE}[*] {Colors.WHITE}Found form, testing POST SQLi...")
                for field in ['username', 'user', 'email']:
                    for payload in test_params.values():
                        data = {field: payload, 'password': 'test'}
                        response = self.session.post(url, data=data, timeout=5)
                        
                        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'oracle']):
                            print(f"{Colors.RED}[!] Possible SQLi via POST param: {Colors.WHITE}{field}")
                            vulnerable = True
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing SQLi: {e}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[✓] {Colors.WHITE}No obvious SQLi vulnerabilities detected")

    def check_xss(self, url):
        """Detecta possíveis vulnerabilidades XSS"""
        print(f"\n{Colors.BLUE}[🔍] {Colors.WHITE}Testing for XSS...")
        
        payloads = [
            '<script>alert("TEHRY_XSS")</script>',
            '<img src=x onerror=alert("TEHRY_XSS")>',
            '"><script>alert("TEHRY_XSS")</script>'
        ]
        
        vulnerable = False
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test GET parameters
            if parsed.query:
                for param in parsed.query.split('&'):
                    key = param.split('=')[0]
                    for payload in payloads:
                        test_url = f"{base_url}?{key}={payload}"
                        response = self.session.get(test_url, timeout=5)
                        
                        if payload in response.text:
                            print(f"{Colors.RED}[!] Possible XSS at: {Colors.WHITE}{test_url}")
                            vulnerable = True
            
            # Test POST if form exists
            if '<form' in self.session.get(url).text.lower():
                print(f"{Colors.BLUE}[*] {Colors.WHITE}Found form, testing POST XSS...")
                for field in ['search', 'query', 'q', 'name']:
                    for payload in payloads:
                        data = {field: payload}
                        response = self.session.post(url, data=data, timeout=5)
                        
                        if payload in response.text:
                            print(f"{Colors.RED}[!] Possible XSS via POST param: {Colors.WHITE}{field}")
                            vulnerable = True
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing XSS: {e}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[✓] {Colors.WHITE}No obvious XSS vulnerabilities detected")

    def check_open_redirect(self, url):
        """Verifica vulnerabilidades de redirecionamento aberto"""
        print(f"\n{Colors.BLUE}[🔍] {Colors.WHITE}Testing for Open Redirects...")
        
        test_urls = [
            f"{url}?redirect=http://evil.com",
            f"{url}?url=//evil.com",
            f"{url}?next=https://evil.com"
        ]
        
        vulnerable = False
        
        try:
            for test_url in test_urls:
                response = self.session.get(test_url, allow_redirects=False, timeout=5)
                
                if 300 <= response.status_code < 400:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        print(f"{Colors.RED}[!] Open redirect found: {Colors.WHITE}{test_url}")
                        print(f"{Colors.RED}    Redirects to: {Colors.WHITE}{location}")
                        vulnerable = True
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing open redirects: {e}")
        
        if not vulnerable:
            print(f"{Colors.GREEN}[✓] {Colors.WHITE}No open redirect vulnerabilities detected")

    def scan_website(self, url):
        """Executa todas as verificações no site"""
        self.show_banner()
        
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        print(f"\n{Colors.GREEN}[*] {Colors.WHITE}Starting scan for: {Colors.CYAN}{url}")
        
        try:
            # Verifica se o site está online
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                print(f"{Colors.YELLOW}[!] Warning: Site returned status {response.status_code}")
            
            # Executa todos os testes
            self.check_sql_injection(url)
            self.check_xss(url)
            self.check_open_redirect(url)
            
            print(f"\n{Colors.GREEN}[✓] {Colors.CYAN}Scan completed!{Colors.RESET}")
        
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[-] Error accessing website: {e}")
        except Exception as e:
            print(f"{Colors.RED}[-] Unexpected error: {e}")

    def run_test_cases(self):
        """Run built-in test cases"""
        test_sites = [
            "http://testphp.vulnweb.com",
            "http://demo.testfire.net"
        ]
        
        for site in test_sites:
            print(f"\n{Colors.YELLOW}[⚡] {Colors.CYAN}Running test against: {site}")
            self.scan_website(site)

if __name__ == "__main__":
    scanner = TehryWebScanner()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            scanner.run_test_cases()
        else:
            target = sys.argv[1]
            scanner.scan_website(target)
    else:
        print(f"{Colors.RED}[!] Usage: python3 tehry_scanner.py <website_url>")
        print(f"{Colors.BLUE}[*] Example: python3 tehry_scanner.py example.com")
        print(f"{Colors.GREEN}[*] Test Mode: python3 tehry_scanner.py --test{Colors.RESET}")