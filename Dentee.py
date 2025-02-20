import requests
import re
import argparse
import subprocess
from bs4 import BeautifulSoup
from colorama import Fore, Style
from prettytable import PrettyTable

# 🔥 Renkler
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# 🔥 CWE Kodları ve CVSS Skorları
CWE_DATABASE = {
    "SQL Injection": ("CWE-89", 9.8),
    "XSS": ("CWE-79", 6.1),
    "LFI": ("CWE-73", 7.5),
    "CSRF": ("CWE-352", 5.3),
    "SSTI": ("CWE-94", 8.2),
    "Admin Panel": ("CWE-200", 4.3),
    "Subdomain Exposure": ("CWE-693", 3.7)
}

# 🔥 Açık Tespit Listesi
found_vulnerabilities = []

# 🔥 SQL Injection Testi
sqli_payloads = ["' OR 1=1 --", "' UNION SELECT 1,2,3 --", "' OR 'x'='x"]
def test_sqli(url):
    for payload in sqli_payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if "sql syntax" in response.text.lower():
            print(RED + f"[!] SQL Injection Açığı Bulundu: {test_url}" + RESET)
            found_vulnerabilities.append("SQL Injection")
            return
    print(GREEN + "[✓] SQL Injection Açığı Yok" + RESET)

# 🔥 XSS Testi
xss_payloads = ["<script>alert(1)</script>", '"><script>alert(1)</script>']
def test_xss(url):
    for payload in xss_payloads:
        response = requests.get(url, params={"q": payload})
        if payload in response.text:
            print(RED + f"[!] XSS Açığı Bulundu: {url}" + RESET)
            found_vulnerabilities.append("XSS")
            return
    print(GREEN + "[✓] XSS Açığı Yok" + RESET)

# 🔥 LFI Testi
lfi_payloads = ["../../../../etc/passwd", "/etc/passwd"]
def test_lfi(url):
    for payload in lfi_payloads:
        response = requests.get(url + payload)
        if "root:x" in response.text:
            print(RED + f"[!] LFI Açığı Bulundu: {url}{payload}" + RESET)
            found_vulnerabilities.append("LFI")
            return
    print(GREEN + "[✓] LFI Açığı Yok" + RESET)

# 🔥 CSRF Testi
def test_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf_token"})
    if csrf_token:
        print(RED + f"[!] CSRF Token Mevcut: {csrf_token['value']}" + RESET)
        found_vulnerabilities.append("CSRF")
    else:
        print(GREEN + "[✓] CSRF Token Yok veya Korumasız" + RESET)

# 🔥 Admin Panel & Önemli Dizinler
admin_pages = ["admin", "admin/login", "administrator", "wp-admin"]
def admin_panel_scan(url):
    for panel in admin_pages:
        test_url = f"{url}/{panel}"
        response = requests.get(test_url)
        if response.status_code == 200:
            print(RED + f"[!] Admin Panel Bulundu: {test_url}" + RESET)
            found_vulnerabilities.append("Admin Panel")
        else:
            print(GREEN + f"[✓] Admin Panel Bulunamadı: {test_url}" + RESET)

# 🔥 Subdomain Tarama
subdomains = ["admin", "dev", "test", "staging"]
def subdomain_enum(url):
    base_url = url.replace("http://", "").replace("https://", "").split("/")[0]
    for sub in subdomains:
        subdomain_url = f"http://{sub}.{base_url}"
        try:
            response = requests.get(subdomain_url)
            if response.status_code == 200:
                print(RED + f"[!] Subdomain Bulundu: {subdomain_url}" + RESET)
                found_vulnerabilities.append("Subdomain Exposure")
        except requests.exceptions.ConnectionError:
            print(GREEN + f"[✓] Subdomain Yok: {subdomain_url}" + RESET)

# 🔥 Nmap ile Port Tarama
def port_scan(url):
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    print(YELLOW + f"[+] Nmap Port Tarama Başlıyor: {domain}" + RESET)
    subprocess.run(["nmap", "-p-", domain])

# 🔥 Risk Skor Tablosu
def print_risk_table():
    print(YELLOW + "\n[🔎] Açıkların Risk Analizi ve Skor Tablosu:" + RESET)
    table = PrettyTable()
    table.field_names = ["Açık Türü", "CWE Kodu", "CVSS Skoru (0-10)"]
    
    for vuln in set(found_vulnerabilities):  
        cwe, score = CWE_DATABASE.get(vuln, ("Bilinmiyor", "Bilinmiyor"))
        table.add_row([vuln, cwe, score])

    print(table)

# 🔥 Banner
def banner():
    print(RED + """
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝
██║  ██║█████╗  ██╔██╗ ██║   ██║   █████╗  █████╗  
██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══╝  
██████╔╝███████╗██║ ╚████║   ██║   ███████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
🔍 OWASP Top 10 Web Pentest Tool 🔍
""" + RESET)

# 🔥 Ana Fonksiyon
def main():
    banner()
    
    parser = argparse.ArgumentParser(description="OWASP Top 10 Web Pentest Tool")
    parser.add_argument("url", help="Hedef URL (örnek: http://site.com)")
    args = parser.parse_args()

    url = args.url

    if not url.startswith("http"):
        url = "http://" + url

    print(YELLOW + f"\n[+] Test Edilen Site: {url}" + RESET)

    test_sqli(url)
    test_xss(url)
    test_lfi(url)
    test_csrf(url)
    admin_panel_scan(url)
    subdomain_enum(url)
    port_scan(url)

    print_risk_table()

if __name__ == "__main__":
    main()
