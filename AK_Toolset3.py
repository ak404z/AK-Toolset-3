#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ===============================================================
#  AK Software License v1.0
#  Copyright (c) 2025 AK (ak404z)
#
#  This software is provided for educational and research purposes
#  only. You are NOT allowed to use this code for:
#      - Illegal activities
#      - Harming individuals or organizations
#      - Unauthorized access or data breaches
#
#  By using this software, you agree that:
#      - The author is not responsible for any misuse.
#      - The tool is provided "AS IS" without any warranty.
#      - You assume full responsibility for any consequences.
#
#  You may modify and redistribute this code ONLY with proper
#  credit to the original author (AK / ak404z).
#
#  Unauthorized commercial use is strictly prohibited.
# ===============================================================
import os
import sys
import time
import requests
import random
import socket
import re
import phonenumbers
from phonenumbers import geocoder, carrier, NumberParseException, number_type, PhoneNumberType, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN = '\033[92m'
BOLD = '\033[1m'
RESET = '\033[0m'

GITHUB_URL = "https://github.com/ak404z"
TELEGRAM_URL = "https://t.me/AKServer404"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.01):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def print_banner():
    clear()
    print(GREEN + r"""
   _____   ____  __. ___________           .__                 __    ________  
  /  _  \ |    |/ _| \__    ___/___   ____ |  |   ______ _____/  |_  \_____  \ 
 /  /_\  \|      <     |    | /  _ \ /  _ \|  |  /  ___// __ \   __\   _(__  < 
/    |    \    |  \    |    |(  <_> |  <_> )  |__\___ \\  ___/|  |    /       \
\____|__  /____|__ \   |____| \____/ \____/|____/____  >\___  >__|   /______  /
        \/        \/                                 \/     \/              \/ 
""" + RESET)
    slow_print(f"{BOLD}{GREEN}        Welcome to AK Toolset 3{RESET}\n", 0.01)
    print(f"{BOLD}{GREEN}  [  GitHub ]: {GITHUB_URL}")
    print(f"  [ Telegram ]: {TELEGRAM_URL}{RESET}")
    print(f"{GREEN}{'-' * 72}{RESET}")
    print(f"{BOLD}{GREEN}  [1] IP Tracker")
    print(f"  [2] Phone Number Lookup")
    print(f"  [3] Username OSINT")
    print(f"  [4] Metadata Extractor")
    print(f"{BOLD}{GREEN}  [5] Domain WHOIS & DNS Analyzer")
    print(f"{BOLD}{GREEN}  [6] Hash Identifier & Cracker")
    print(f"{BOLD}{GREEN}  [7] Simple Port Scanner")
    print(f"{BOLD}{GREEN}  [8] Admin Panel Enumerator")
    print(f"{BOLD}{GREEN}  [9] Fake Card Generator")
    print(f"{BOLD}{GREEN}  [10] JS Secrets Finder")
    print(f"  [0] Exit{RESET}")
    print(f"{GREEN}{'-' * 72}{RESET}")

def ip_tracker():
    clear()
    print(f"{BOLD}{GREEN}--- IP Tracker ---{RESET}")
    ip = input(f"{GREEN}Enter IP address (or leave empty for your IP): {RESET}").strip()
    if not ip:
        ip = requests.get("https://api.ipify.org").text
    try:
        
        url = f"https://ipinfo.io/{ip}/json"
        url2 = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,reverse,proxy,mobile,hosting,query"
        data = requests.get(url, timeout=10).json()
        data2 = requests.get(url2, timeout=10).json()
        print(f"{BOLD}{GREEN}\nResults for IP: {ip}\n{'-'*55}")
        print(f"IP Address  : {ip}")
        print(f"Hostname    : {data2.get('reverse', 'N/A')}")
        print(f"Continent   : {data2.get('continent','N/A')} ({data2.get('continentCode','N/A')})")
        print(f"Country     : {data2.get('country','N/A')} ({data2.get('countryCode','N/A')})")
        print(f"Region      : {data2.get('regionName','N/A')} / {data2.get('region','N/A')}")
        print(f"City        : {data2.get('city','N/A')}")
        print(f"District    : {data2.get('district','N/A')}")
        print(f"ZIP         : {data2.get('zip','N/A')}")
        print(f"Coordinates : {data.get('loc','N/A')} | https://maps.google.com/?q={data.get('loc','')}")
        print(f"Timezone    : {data2.get('timezone','N/A')}")
        print(f"ISP         : {data2.get('isp','N/A')}")
        print(f"Org/ASN     : {data2.get('org','N/A')} | {data2.get('as','N/A')}")
        print(f"Mobile      : {data2.get('mobile', 'N/A')}   Proxy/VPN : {data2.get('proxy', 'N/A')}   Hosting : {data2.get('hosting', 'N/A')}")
        print(f"Google Map  : https://maps.google.com/?q={data.get('loc','')}")
        print(f"IP Range    : {data.get('range', 'N/A') if 'range' in data else 'N/A'}")
        print(f"Org (ipinfo): {data.get('org', 'N/A')}")
        print(f"ASN (ipinfo): {data.get('asn', {}).get('asn', 'N/A') if 'asn' in data else 'N/A'}")
        print(f"Anycast     : {data.get('anycast', 'N/A')}")
        print('-' * 55 + RESET)
    except Exception as e:
        print(f"{GREEN}Error: {e}{RESET}")
    input(f"{GREEN}Press Enter to return...{RESET}")

def phone_lookup():
    clear()
    print(f"{BOLD}{GREEN}--- Phone Number Lookup ---{RESET}")
    number = input(f"{GREEN}Enter phone number with country code (e.g., +972...): {RESET}").strip()
    try:
        parsed = phonenumbers.parse(number, None)
        country_en = geocoder.description_for_number(parsed, "en")
        country_ar = geocoder.description_for_number(parsed, "ar")
        sim = carrier.name_for_number(parsed, "en")
        is_valid = phonenumbers.is_valid_number(parsed)
        number_t = number_type(parsed)
        num_kind = {PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Landline", 
                    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Mobile/Landline", PhoneNumberType.VOIP: "VoIP"}.get(number_t, "Unknown")
        timezone_str = ', '.join(timezone.time_zones_for_number(parsed)) if timezone.time_zones_for_number(parsed) else "N/A"
        print(f"{BOLD}{GREEN}\nPhone Number Info\n{'-'*40}")
        print(f"Number       : {number}")
        print(f"E164         : {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        print(f"National     : {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}")
        print(f"Country (EN) : {country_en}")
        print(f"Country (AR) : {country_ar}")
        print(f"Country Code : +{parsed.country_code}")
        print(f"Region Code  : {phonenumbers.region_code_for_number(parsed)}")
        print(f"Carrier      : {sim or 'N/A'}")
        print(f"Type         : {num_kind}")
        print(f"Valid        : {is_valid}")
        print(f"Timezone     : {timezone_str}")
        print(f"Country Info : https://countrycode.org/{phonenumbers.region_code_for_number(parsed)}")
        print('-' * 40 + RESET)
    except NumberParseException:
        print(f"{GREEN}Invalid phone number format!{RESET}")
    input(f"{GREEN}Press Enter to return...{RESET}")

def check_profile(name, url):
    """Returns (name, url, result)"""
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            return (name, url, True)
        elif r.status_code == 302 and "login" not in r.url:
            return (name, url, True)
        else:
            return (name, url, False)
    except:
        return (name, url, False)

def username_osint():
    clear()
    print(f"{BOLD}{GREEN}--- Username OSINT ---{RESET}")
    username = input(f"{GREEN}Enter username: {RESET}").strip()
    
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Facebook": f"https://facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Medium": f"https://medium.com/@{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Dev.to": f"https://dev.to/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "About.me": f"https://about.me/{username}",
        "Ask.fm": f"https://ask.fm/{username}",
        "VK": f"https://vk.com/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Badoo": f"https://badoo.com/en/{username}/",
        "Replit": f"https://replit.com/@{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}/",
        "Kaggle": f"https://kaggle.com/{username}",
        "ProductHunt": f"https://www.producthunt.com/@{username}",
        "HackerRank": f"https://www.hackerrank.com/{username}",
        "StackOverflow": f"https://stackoverflow.com/users/{username}",
        "Codeforces": f"https://codeforces.com/profile/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "NameMC (Minecraft)": f"https://namemc.com/profile/{username}",
        "OpenSea": f"https://opensea.io/{username}",
        "WordPress": f"https://profiles.wordpress.org/{username}",
        "BuyMeACoffee": f"https://www.buymeacoffee.com/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Fiverr": f"https://www.fiverr.com/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "Imgur": f"https://imgur.com/user/{username}",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Quora": f"https://www.quora.com/profile/{username}",
        "TripAdvisor": f"https://tripadvisor.com/members/{username}",
        "AngelList": f"https://angel.co/{username}",
        "Strava": f"https://www.strava.com/athletes/{username}",
        "500px": f"https://500px.com/{username}",
        "Disqus": f"https://disqus.com/by/{username}/",
    }
    print(f"{BOLD}{GREEN}\nChecking platforms for: {username} (this may take a few seconds)\n{'-'*55}")

    found = []
    notfound = []

    with ThreadPoolExecutor(max_workers=18) as executor:
        futures = [executor.submit(check_profile, name, url) for name, url in platforms.items()]
        for future in as_completed(futures):
            name, url, exists = future.result()
            if exists:
                found.append((name, url))
            else:
                notfound.append(name)

    for name, url in found:
        print(f"{GREEN}[+] {name}: {url} [Found]")
    for name in notfound:
        print(f"{GREEN}[-] {name}: Not Found")
    print('-' * 55 + RESET)
    input(f"{GREEN}Press Enter to return...{RESET}")

def install_missing_libs():
    import importlib.util
    pkgs = [
        ("exifread", "exifread"),
        ("PyPDF2", "PyPDF2"),
        ("python-docx", "docx"),
        ("mutagen", "mutagen"),
    ]
    for pip_name, import_name in pkgs:
        if importlib.util.find_spec(import_name) is None:
            print(f"{GREEN}Installing {pip_name} ...{RESET}")
            os.system(f"pip install {pip_name}")

install_missing_libs()

def is_displayable(val):
    """فلترة النتائج التي ليست نص واضح أو ليست dict/json"""
    if isinstance(val, bytes):
        return False
    if isinstance(val, (dict, list, set)):
        return True
    s = str(val)
    if len(s) > 100:
        return False
    if s.startswith("b'") or s.startswith('b"'):
        return False
    return True

def pretty_print_json(val, prefix=""):
    import json
    try:
        if isinstance(val, str):
            obj = json.loads(val)
        else:
            obj = val
        for k, v in obj.items():
            print(f"{GREEN}{prefix}{k}: {v}{RESET}")
    except Exception:
        print(f"{GREEN}{prefix}{val}{RESET}")

def metadata_extractor():
    import exifread
    import PyPDF2
    import docx
    import mutagen
    import json

    clear()
    print(f"{BOLD}{GREEN}--- Metadata Extractor ---{RESET}")
    path = input(f"{GREEN}Enter file path (image/pdf/docx/mp3...): {RESET}").strip()
    if not os.path.isfile(path):
        print(f"{GREEN}File not found!{RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    ext = os.path.splitext(path)[1].lower()

    print(f"{BOLD}{GREEN}\nExtracting metadata for: {path}\n{'-'*55}")
    try:
        if ext in [".jpg", ".jpeg", ".tiff", ".png"]:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=True)
                if not tags:
                    print(f"{GREEN}No EXIF metadata found.")
                for tag, value in tags.items():
                    if "Thumbnail" in tag or not is_displayable(value):
                        continue
                    val_str = str(value)
                    if val_str.startswith("{") and val_str.endswith("}"):
                        try:
                            pretty_print_json(val_str, prefix=f"{tag} > ")
                            continue
                        except: pass
                    print(f"{GREEN}{tag}{RESET}: {val_str}")
        elif ext == ".pdf":
            with open(path, "rb") as f:
                pdf = PyPDF2.PdfReader(f)
                info = pdf.metadata
                if info:
                    for k, v in info.items():
                        if is_displayable(v):
                            print(f"{GREEN}{k}{RESET}: {v}")
                else:
                    print(f"{GREEN}No PDF metadata found.")
        elif ext == ".docx":
            doc = docx.Document(path)
            props = doc.core_properties
            for attr in dir(props):
                if not attr.startswith('_') and not callable(getattr(props, attr)):
                    val = getattr(props, attr)
                    if val and is_displayable(val):
                        print(f"{GREEN}{attr}{RESET}: {val}")
        elif ext in [".mp3", ".flac", ".ogg", ".wav", ".mp4", ".m4a"]:
            audio = mutagen.File(path)
            if audio:
                for key, value in audio.items():
                    if is_displayable(value):
                        print(f"{GREEN}{key}{RESET}: {value}")
                if hasattr(audio, "info"):
                    for key, value in audio.info.__dict__.items():
                        if is_displayable(value):
                            print(f"{GREEN}{key}{RESET}: {value}")
            else:
                print(f"{GREEN}No metadata found.")
        else:
            print(f"{GREEN}Unsupported file type or no extractor for this format.{RESET}")
    except Exception as e:
        print(f"{GREEN}Error extracting metadata: {e}{RESET}")
    print('-' * 55 + RESET)
    input(f"{GREEN}Press Enter to return...{RESET}")

def install_missing_libs_dns():
    import importlib.util
    pkgs = [
        ("whois", "whois"),
        ("dnspython", "dns"),
    ]
    for pip_name, import_name in pkgs:
        if importlib.util.find_spec(import_name) is None:
            print(f"{GREEN}Installing {pip_name} ...{RESET}")
            os.system(f"pip install {pip_name}")

install_missing_libs_dns()

def domain_whois_dns_analyzer():
    import whois
    import dns.resolver
    import socket

    clear()
    print(f"{BOLD}{GREEN}--- Domain WHOIS & DNS Analyzer ---{RESET}")
    domain = input(f"{GREEN}Enter domain (e.g. example.com): {RESET}").strip().lower()
    if not domain:
        print(f"{GREEN}No domain provided!{RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    print(f"{BOLD}{GREEN}\n[SUMMARY]{RESET}")
    print(f"{GREEN}Domain:{RESET} {domain}")

    # WHOIS SECTION
    print(f"\n{BOLD}{GREEN}[ WHOIS INFO ]{RESET}")
    try:
        w = whois.whois(domain)
        registrar = w.get('registrar', 'N/A')
        state = w.get('status', 'N/A')
        if isinstance(state, list): state = ', '.join(state)
        print(f"{GREEN}Registrar:{RESET} {registrar}")
        print(f"{GREEN}Status   :{RESET} {state}")

        whois_fields = [
            ('Domain Name', 'domain_name'),
            ('Registrar', 'registrar'),
            ('Creation Date', 'creation_date'),
            ('Expiration Date', 'expiration_date'),
            ('Updated Date', 'updated_date'),
            ('Emails', 'emails'),
            ('Name Servers', 'name_servers'),
        ]
        for label, field in whois_fields:
            val = w.get(field)
            if val:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                print(f"{GREEN}{label}:{RESET} {val}")
    except Exception as e:
        print(f"{GREEN}WHOIS Error: {e}{RESET}")

    # DNS SECTION
    print(f"\n{BOLD}{GREEN}[ DNS RECORDS ]{RESET}")
    dns_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "PTR"]
    for t in dns_types:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=6)
            values = [str(rdata) for rdata in answers]
            if values:
                print(f"{GREEN}{t} Record(s):{RESET}")
                for v in values:
                    print(f"   {v}")
            else:
                print(f"{GREEN}{t} Record(s):{RESET} Not Found")
        except Exception:
            print(f"{GREEN}{t} Record(s):{RESET} Not Found")

    # Reverse IP
    try:
        a_records = dns.resolver.resolve(domain, "A")
        ip = str(a_records[0])
        rev = None
        try:
            rev = socket.gethostbyaddr(ip)[0]
        except:
            rev = "N/A"
        print(f"\n{GREEN}Resolved IP   :{RESET} {ip}")
        print(f"{GREEN}Reverse DNS   :{RESET} {rev}")
    except Exception:
        print(f"\n{GREEN}Resolved IP   :{RESET} Not Found")
        print(f"{GREEN}Reverse DNS   :{RESET} N/A")

    # Cloudflare / WAF / CDN Detection
    print(f"\n{BOLD}{GREEN}[ PROTECTION / HOSTING ]{RESET}")
    waf_detected = "Unknown"
    try:
        a_records = dns.resolver.resolve(domain, "A")
        ips = [str(r) for r in a_records]
        cloudflare_ranges = ["104.", "172.", "173.", "141.101.", "162.158."]
        incapsula_ranges = ["45.64.64.", "103.28.248.", "107.154.", "45.223."]
        sucuri_ranges = ["192.124.249."]
        akamai_ranges = ["23.", "184.", "2.22.", "2.16.", "23.32."]
        found = []
        for ip in ips:
            if any(ip.startswith(x) for x in cloudflare_ranges):
                found.append("Cloudflare")
            elif any(ip.startswith(x) for x in incapsula_ranges):
                found.append("Incapsula/Imperva")
            elif any(ip.startswith(x) for x in sucuri_ranges):
                found.append("Sucuri")
            elif any(ip.startswith(x) for x in akamai_ranges):
                found.append("Akamai")
        if found:
            waf_detected = "/".join(set(found))
        else:
            waf_detected = "Not Detected"
    except Exception:
        waf_detected = "Unknown"
    print(f"{GREEN}WAF/CDN/Protection:{RESET} {waf_detected}")

    print(f"{BOLD}{GREEN}\n[ QUICK PORT SCAN ]{RESET}")
    for port in [80, 443]:
        try:
            sock = socket.create_connection((domain, port), timeout=2)
            sock.close()
            print(f"{GREEN}Port {port} OPEN{RESET}")
        except Exception:
            print(f"{GREEN}Port {port} CLOSED{RESET}")

    print(f"\n{GREEN}{'-'*55}{RESET}")
    input(f"{GREEN}Press Enter to return...{RESET}")

def hash_identifier(hash_str):
    hash_types = []
    hlen = len(hash_str)
    if re.fullmatch(r'[a-fA-F0-9]{32}', hash_str):
        hash_types.append("MD5")
    if re.fullmatch(r'[a-fA-F0-9]{40}', hash_str):
        hash_types.append("SHA1")
    if re.fullmatch(r'[a-fA-F0-9]{64}', hash_str):
        hash_types.append("SHA256")
    if re.fullmatch(r'[a-fA-F0-9]{128}', hash_str):
        hash_types.append("SHA512")
    if re.fullmatch(r'[a-fA-F0-9]{16}', hash_str):
        hash_types.append("MySQL / DES / CRC128")
    if re.fullmatch(r'[a-fA-F0-9]{24}', hash_str):
        hash_types.append("SHA-1(Unix)")
    if re.fullmatch(r'[a-fA-F0-9]{13}', hash_str):
        hash_types.append("DES(Unix)")
    if re.fullmatch(r'[a-fA-F0-9]{48}', hash_str):
        hash_types.append("SHA384")
    if re.fullmatch(r'[a-fA-F0-9]{96}', hash_str):
        hash_types.append("SHA384")
    if hash_str.startswith('$2a$') or hash_str.startswith('$2b$'):
        hash_types.append("bcrypt")
    if hash_str.startswith('$1$'):
        hash_types.append("MD5 Crypt")
    if hash_str.startswith('$6$'):
        hash_types.append("SHA512 Crypt")
    if hash_str.startswith('$5$'):
        hash_types.append("SHA256 Crypt")
    return hash_types if hash_types else ["Unknown/Custom"]

def hash_identifier_and_cracker():
    import requests
    clear()
    print(f"{BOLD}{GREEN}--- Hash Identifier & Cracker ---{RESET}")
    hash_input = input(f"{GREEN}Enter the hash to identify & crack: {RESET}").strip()
    if not hash_input:
        print(f"{GREEN}No hash entered!{RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    print(f"\n{GREEN}Hash: {RESET}{hash_input}")
    hash_types = hash_identifier(hash_input)
    print(f"{GREEN}Detected Type(s): {RESET}{', '.join(hash_types)}")

    print(f"{GREEN}Searching online for cracked value...{RESET}")

    try:
        url = f"https://hashtoolkit.com/decrypt-hash/?hash={hash_input}"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; AK-Toolset/1.0)"}
        resp = requests.get(url, headers=headers, timeout=12)
        found = False
        matches = re.findall(r"hash\">.*?</span>.*?<span.*?class=\"res-text\">(.*?)</span>", resp.text, re.DOTALL)
        if matches:
            pwd = matches[0].strip()
            print(f"{GREEN}Cracked Password:{RESET} {pwd}")
            found = True
        else:
            print(f"{GREEN}No plain password found online.{RESET}")
        print(f"{GREEN}Source:{RESET} {url}")
    except Exception as e:
        print(f"{GREEN}Error searching online: {e}{RESET}")
    print("-"*55 + RESET)
    input(f"{GREEN}Press Enter to return...{RESET}")

def port_scanner():
    import threading

    clear()
    print(f"{BOLD}{GREEN}--- Advanced Port Scanner (Fast, Auto-Ports) ---{RESET}")
    target = input(f"{GREEN}Enter Target IP or Domain: {RESET}").strip()
    if not target:
        print(f"{GREEN}No target entered!{RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    target = re.sub(r'^(https?://)', '', target, flags=re.I)
    target = target.strip('/')

    try:
        target_ip = socket.gethostbyname(target)
        print(f"{GREEN}Resolved IP: {RESET}{target_ip}\n")
    except Exception as e:
        print(f"{GREEN}Invalid domain or IP! ({e}){RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    ports = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",139:"NetBIOS",143:"IMAP",
        443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP-SSL",993:"IMAPS",995:"POP3S",3306:"MySQL",
        3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt",53:"DNS",5900:"VNC",1723:"PPTP",1521:"Oracle",
        5432:"PostgreSQL",6379:"Redis",9200:"Elasticsearch",27017:"MongoDB",389:"LDAP",135:"MS RPC",
        1025:"NFS",111:"RPCBind",6001:"X11",19:"Chargen",79:"Finger",2000:"Cisco SCCP",5000:"UPnP",
        5500:"VNC-2",5800:"VNC-Web",49152:"MS RPC",49154:"MS RPC",161:"SNMP",137:"NetBIOS-NS",
        138:"NetBIOS-DGM",6667:"IRC",7001:"WebLogic",8081:"HTTP-Alt2",8181:"HTTP-Alt3",
        8888:"HTTP-Proxy",9000:"CSlistener",9200:"ES",11211:"Memcached",27017:"MongoDB"
    }

    open_ports = []
    lock = threading.Lock()

    def scan_port(port, service):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                try:
                    s.sendall(b"\r\n")
                    banner = s.recv(120).decode(errors='ignore').strip()
                except:
                    banner = ""
                with lock:
                    open_ports.append((port, service, banner))
            s.close()
        except:
            pass

    threads = []
    for port, service in ports.items():
        t = threading.Thread(target=scan_port, args=(port, service))
        threads.append(t)
        t.start()
        if len(threads) >= 100:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    print("\n" + "-"*65 + RESET)
    if open_ports:
        print(f"{GREEN}Open Ports:{RESET}")
        for port, service, banner in sorted(open_ports):
            print(f"{GREEN}- Port {port:<5} [{service}] ", end="")
            if banner:
                print(f"{BOLD}| Banner: {banner[:60]}{RESET}")
            else:
                print()
    else:
        print(f"{GREEN}No open ports found on target.{RESET}")
    print("-"*65 + RESET)
    input(f"{GREEN}Press Enter to return...{RESET}")

def admin_login_finder():
    import threading

    clear()
    print(f"{BOLD}{GREEN}--- Admin Panel Enumerator ---{RESET}")
    domain = input(f"{GREEN}Enter domain (e.g example.com): {RESET}").strip().lower()
    if not domain:
        print(f"{GREEN}No domain provided!{RESET}")
        input(f"{GREEN}Press Enter to return...{RESET}")
        return

    print(f"{GREEN}Finding subdomains...{RESET}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent":"AK-Toolset/1.0"})
        data = resp.json() if resp.status_code == 200 else []
    except Exception:
        data = []

    subdomains = set()
    for entry in data:
        name = entry.get("name_value") or entry.get("common_name")
        if not name: continue
        for n in str(name).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                subdomains.add(n)
    if not subdomains:
        subdomains = {domain}

    login_paths = [
        "login", "signin", "user", "users/login", "users/signin", "wp-login.php",
        "admin", "admin/login", "administrator", "cpanel", "auth", "dashboard",
        "manage", "panel", "backend", "console", "moderator", "login.php",
        "admin.php", "login.html", "adminarea", "siteadmin", "adminpanel",
        "member/login", "members/login", "secure", "secure/login", "portal", "access",
        "controlpanel", "staff", "support", "login.aspx", "admin/login.aspx",
        "administrator/login", "system", "accounts", "account/login", "users/sign-in"
    ]

    candidates = []
    for sd in subdomains:
        for p in login_paths:
            candidates.append(f"https://{sd}/{p}")
            candidates.append(f"http://{sd}/{p}")
    for p in login_paths:
        candidates.append(f"https://{domain}/{p}")
        candidates.append(f"http://{domain}/{p}")

    uniq_candidates = []
    seen = set()
    for u in candidates:
        if u not in seen:
            seen.add(u)
            uniq_candidates.append(u)

    found_logins = []
    lock = threading.Lock()

    def check_url(url):
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent":"AK-Toolset/2.0"})
            if r.status_code in [200, 401, 403]:
                text = r.text.lower()
                title = ""
                m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I)
                if m: title = m.group(1).lower()
                if (
                    "login" in url.lower() or "signin" in url.lower() or
                    "login" in title or "sign" in title or "auth" in title or
                    "تسجيل دخول" in title or "كلمة المرور" in text or "كلمة السر" in text or
                    re.search(r'name=["\']?password["\']?', r.text, re.I) or
                    re.search(r'type=["\']?password["\']?', r.text, re.I)
                ):
                    with lock:
                        found_logins.append(url)
                        print(f"{GREEN}{url}{RESET}")
        except Exception:
            pass

    print(f"{GREEN}Scanning possible login pages...{RESET}")
    threads = []
    for url in uniq_candidates:
        t = threading.Thread(target=check_url, args=(url,))
        threads.append(t)
        t.start()
        if len(threads) >= 30: 
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()

    if not found_logins:
        print(f"{GREEN}No login pages found on {domain}.{RESET}")

    print("-"*55 + RESET)
    input(f"{GREEN}Press Enter to return...{RESET}")

BOLD = "\033[1m"
GREEN = "\033[92m"
WHITE = "\033[97m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def clear():
    import os
    os.system("cls" if os.name == "nt" else "clear")

def fake_card_generator():
    clear()
    print(f"{BOLD}{GREEN}Fake Card Generator{RESET}\n")
    print(f"{CYAN}[1] Visa{RESET}   {RED}[2] MasterCard{RESET}   {GREEN}[3] Amex{RESET}   {YELLOW}[4] Random{RESET}")
    opt = input(f"Select option: ").strip()
    if opt == "1":
        prefix, length, name, color = "4", 16, "Visa", CYAN
    elif opt == "2":
        prefix, length, name, color = random.choice(["51", "52", "53", "54", "55"]), 16, "MasterCard", RED
    elif opt == "3":
        prefix, length, name, color = random.choice(["34", "37"]), 15, "Amex", GREEN
    else:
        choice = random.choice([
            ("4", 16, "Visa", CYAN),
            (random.choice(["51", "52", "53", "54", "55"]), 16, "MasterCard", RED),
            (random.choice(["34", "37"]), 15, "Amex", GREEN)
        ])
        prefix, length, name, color = choice

    print(f"\n{color}Generating 10 fake {name} card numbers:{RESET}\n")

    def random_luhn_card(prefix, length):
        number = list(str(prefix))
        while len(number) < (length - 1):
            number.append(str(random.randint(0,9)))
        def luhn_digit(num):
            total = 0
            rev = [int(x) for x in num[::-1]]
            for i, n in enumerate(rev):
                if i % 2 == 0:
                    n *= 2
                    if n > 9: n -= 9
                total += n
            return (10 - (total % 10)) % 10
        d = luhn_digit(number)
        number.append(str(d))
        return "".join(number)

    for i in range(10):
        card_num = random_luhn_card(prefix, length)
        mm = str(random.randint(1,12)).zfill(2)
        yy = str(random.randint(26, 32))
        expiry = f"{mm}/{yy}"
        if name == "Amex":
            cvv = str(random.randint(1000,9999))
        else:
            cvv = str(random.randint(100,999))
        print(f"{color}{BOLD}[{i+1}] {card_num}  |  Exp: {expiry}  |  CVV: {cvv}{RESET}")

    print(f"\n{color}All cards are FAKE{RESET}")
    input("Press Enter to return...")

def js_secrets_finder():
    import re
    import requests
    from urllib.parse import urljoin, urlparse

    clear()
    print(f"{BOLD}{GREEN}--- JS Secrets Finder ---{RESET}")
    target = input(f"{GREEN}Enter website (example: https://site.com): {RESET}").strip()
    if not target.startswith("http"):
        target = "https://" + target

    print(f"{YELLOW}\nCollecting JavaScript files and URLs...{RESET}")
    try:
        r = requests.get(target, timeout=8, headers={"User-Agent":"AK-Toolset/3"})
    except:
        print(f"{RED}Failed to connect to website.{RESET}")
        input("Press Enter to return...")
        return

    js_files = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', r.text, re.I)
    urls_in_html = re.findall(r'https?://[^\s"\'<>]+', r.text)
    js_links = [urljoin(target, src) for src in js_files if src.strip()]
    js_cdn = [u for u in urls_in_html if u.endswith('.js') and u not in js_links]
    js_links += js_cdn
    js_links = list(dict.fromkeys(js_links))  # إزالة التكرار

    if not js_links:
        print(f"{RED}No JavaScript files found!{RESET}")
        input("Press Enter to return...")
        return

    print(f"{GREEN}\nFound {len(js_links)} JS files:{RESET}")
    for link in js_links:
        print(f"{WHITE}- {link}{RESET}")

    secret_patterns = {
        "API Key": r"(?i)(api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{12,50}['\"]?)",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Firebase Secret": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}",
        "Amazon AWS Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret": r"(?i)(aws.+[\'\"]([A-Za-z0-9/+=]{40})[\'\"])",
        "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
        "Twilio Key": r"SK[0-9a-fA-F]{32}",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "Facebook Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "Heroku Key": r"(?i)heroku[\s:=\'\"]+([0-9a-f]{32,40})",
        "Password in Code": r"(?i)(password\s*[=:]\s*['\"][^'\"]+['\"])",
        "JWT Token": r"eyJ[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\.\-_]{10,200}",
        "Access Token": r"(?i)(access[_-]?token\s*[=:]\s*['\"][A-Za-z0-9\-_]{10,200}['\"])",
        "Secret Key": r"(?i)(secret[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{8,50}['\"])",
        "Private URL": r"https?://[A-Za-z0-9_\-\.]+/[A-Za-z0-9_\-/%]+",
        "Hash (MD5/SHA)": r"\b([a-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b",
        "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "Config/Env": r"(?i)(config|env)[._-]?(key|secret|token)?[=:]['\"]?[\w\-_\.\/@]{8,}['\"]?"
    }

    total_secrets = 0
    all_secrets = []

    print(f"\n{YELLOW}Scanning for secrets in JS files...{RESET}\n")
    for js in js_links:
        print(f"{CYAN}Checking: {js}{RESET}")
        try:
            content = requests.get(js, timeout=8, headers={"User-Agent":"AK-Toolset/3"}).text
        except:
            print(f"{RED}Could not load.{RESET}")
            continue
        found_in_this = 0
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, content)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                if m and m not in all_secrets:
                    found_in_this += 1
                    total_secrets += 1
                    all_secrets.append(m)
                    print(f"{YELLOW}{BOLD}[{name}]{RESET} {WHITE}{m}{RESET}")
        if not found_in_this:
            print(f"{GREEN}No secrets in this file.{RESET}")
        else:
            print(f"{RED}--- {found_in_this} secrets found here ---{RESET}")

    print(f"\n{BOLD}{GREEN}Total secrets found: {total_secrets}{RESET}")
    if total_secrets == 0:
        print(f"{GREEN}No secrets found in any JS files.{RESET}")
    input("\nPress Enter to return...")

def main():
    try:
        import phonenumbers
    except ImportError:
        print("Installing phonenumbers library...")
        os.system("pip install phonenumbers")
        print("Restart the program after installation.")
        sys.exit(1)

    while True:
        print_banner()
        choice = input(f"{BOLD}{GREEN}Select an option > {RESET}")
        if choice == "1":
            ip_tracker()
        elif choice == "2":
            phone_lookup()
        elif choice == "3":
            username_osint()
        elif choice == "4":
            metadata_extractor()
        elif choice == "5":
            domain_whois_dns_analyzer()
        elif choice == "6":
            hash_identifier_and_cracker()
        elif choice == "7":
            port_scanner()
        elif choice == "8":
            admin_login_finder()
        elif choice == "9":
            fake_card_generator()
        elif choice == "10":
            js_secrets_finder()
        elif choice == "0":
            slow_print(f"{GREEN}Exiting... Stay Like AK (●'◡'●)!{RESET}")
            sys.exit(0)
        else:
            print(f"{BOLD}{GREEN}Invalid option, try again!{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()