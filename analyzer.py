import sys
import email
import re
import requests
import base64
import os
import hashlib
from bs4 import BeautifulSoup
from dotenv import load_dotenv
load_dotenv()

email_file = sys.argv[1]

with open(email_file, 'r') as f:
    msg = email.message_from_file(f)

print("From:", msg["From"])
print("To:", msg["To"])
print("Subject:", msg["Subject"])
print("Date:", msg["Date"])
print("Reply-To:", msg["Reply-To"])
print("Return-Path:", msg["Return-Path"])
print("X-Originating-IP", msg["X-Originating-IP"])
print("Authentication-Results:", msg["Authentication-Results"])

# detectamos qué tipo de mensaje es

body = ""

if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            print("Body:", body)
else:
    body = msg.get_payload()
    print("Body:", body)

urls = re.findall(r'\bhttps?://\S+', body)
print("URLs:", urls)

# hacemos una funcion defang

def defang(url):
    url = url.replace("http", "hxxp")
    url = url.replace("://", "[://]")
    url = url.replace(".", "[.]")
    return url

print("URLs defangeadas:")
for url in urls:
    print("   -", defang(url))

# hacemos match de deteccion entre diferentes headers

def extract_email(header):
    if header is None:
        return None
    match = re.search(r'<(.+?)>', header)
    if match:
        return match.group(1)
    else:
        return header # si no tiene <> el headaer es el email

from_email = extract_email(msg["From"])
reply_to_email = extract_email(msg["Reply-To"])
return_path_email = extract_email(msg["Return-Path"])

print("\nMISMATCH DETECTION")
print(f"From: {from_email}")
print(f"Reply-To: {reply_to_email}")
print(f"Return-Path: {return_path_email}")

if reply_to_email and from_email != reply_to_email:
    print("ATENCIÓN: From != Reply-To")

if return_path_email and from_email != return_path_email:
    print("ATENCIÓN: From != Return-Path")


# detectamos extensiones

exclude_extensions = [".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lnk", ".iso", ".img", ".hta", ".msi", ".dll"]

# buscamos mas de una extensión en el filename

def has_double_extension(filename):
    if filename.count(".") > 1:
        return True
    else:
        return False

def attachments_check(msg):
    print("\n Análisis de archivos adjuntos")

    if not msg.is_multipart():
        print("No hay archivos adjuntos.")
        return
    
    attachments_found = False

    for part in msg.walk():
        filename = part.get_filename()

        if filename:
            attachments_found = True
            print(f" Adjunto encontrado: {filename}")
            if has_double_extension(filename):
                print("ATENCIÓN: archivo con extensiones dobles")
            
            # detectamos ahora si una extension esta en exclude_extensions
            for ext in exclude_extensions:
                if filename.lower().endswith(ext):
                    print(f"ATENCIÓN: extensión sospechosa: {ext}")
                    break

            # calcular hash SHA256 del adjunto
            content = part.get_payload(decode=True)
            if content:
                hash_sha256 = hashlib.sha256(content).hexdigest()
                print(f"   SHA256: {hash_sha256}")

    if not attachments_found:
        print("No se encontraron archivos adjuntos")

attachments_check(msg)

# buscamos tracking pixels en el html

def detect_tracking_pixel(msg):
    print("\n-- Detección de tracking pixels")

    if not msg.is_multipart():
        print("No existe contenido HTML")
        return

    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html, 'html.parser')

            images = soup.find_all('img')
            for img in images:
                width = img.get('width', '')
                height = img.get('height', '')
                
                if width in ['0', '1'] or height in ['0', '1']:
                    src = img.get('src', 'unknown')
                    print(f"ATENCIÓN: tracking pixel detectado: {src}")

detect_tracking_pixel(msg)

# ahora hacemos consulta a virustotal con su api

def check_virustotal(url, api_key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        return malicious
    else:
        return None

print("\nAnálisis de URLs con VirusTotal")

for url in urls:
    api_key = os.getenv("api_vt")
    vt_score = check_virustotal(url, api_key)
    if vt_score is not None:
        if vt_score >= 3:
            print(f"{url} - Detectado como malicioso por {vt_score} motores.")
        elif vt_score > 0:
            print(f"{url} - Posible sospechoso. Detectado por {vt_score} motores.")
        else:
            print(f"{url} - Limpio. No se han encontrado detecciones maliciosas.")
    else:
        print(f"No se pudo obtener el puntaje para la URL: {url}")

keywords = ["urgent", "important", "action", "now", "immediately", "important", "verify", "expires"]

def detect_keywords(body):
    body = body.lower()
    found = []
    for keyword in keywords:
        if keyword in body:
            found.append(keyword)
    if found:
        print(f"Palabra sospechosa encontrada: {', '.join(found)}")

detect_keywords(body)
