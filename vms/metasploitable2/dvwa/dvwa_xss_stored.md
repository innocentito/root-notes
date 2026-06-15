# DVWA XSS Stored – Metasploitable2

**Target:** Metasploitable2
**Attacker:** Kali Linux
**Category:** Cross Site Scripting (Stored)
**App:** DVWA (Damn Vulnerable Web Application)

---

## How It Works

Stored XSS is the most dangerous type of XSS because the payload gets saved in the database. Every user who visits the page gets hit, not just someone who clicks a crafted link. The attacker injects once and it fires forever until someone cleans the database.

DVWA's Stored XSS page is a guestbook. Two input fields: Name and Message. You sign the guestbook and your entry shows up for everyone. The entries are stored in a MySQL database and loaded every time the page is rendered. If one of those entries contains JavaScript, every visitor's browser executes it.

This is the difference from Reflected XSS. Reflected requires tricking each victim into clicking a link. Stored is fire and forget. One injection, every visitor is a victim.

---

## Low Security

No filtering on either field. Both Name and Message take raw input and store it in the database without any sanitization.

**1. Set DVWA Security to Low.**

**2. Enter a basic XSS payload.** Try the Message field first:

- Name: `test`
- Message: `<script>alert('XSS')</script>`

**3. Submit.** The alert fires immediately because the page reloads and renders your guestbook entry. Refresh the page and it fires again. That's the stored part.

**4. Try the Name field:**

- Name: `<script>alert('XSS')</script>`
- Message: `test`

This won't work because the Name field has a `maxlength="10"` attribute in the HTML. The payload gets cut off.

### Bypassing maxlength

Open browser DevTools (F12), find the Name input element, and change `maxlength="10"` to `maxlength="100"` or just delete the attribute entirely. Now the full payload fits.

This is a client side restriction. The HTML attribute only tells the browser to limit input length. The server doesn't check the length at all. You could also bypass it with curl or Burp Suite by sending the request directly without going through the browser form.

The PHP code for Low:

```php
$message = trim($_POST['mtxMessage']);
$name = trim($_POST['txtName']);
$message = stripslashes($message);
$message = ((isset($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string(...) : ...);
$name = ((isset($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string(...) : ...);
$query = "INSERT INTO guestbook (comment, name) VALUES ('$message','$name')";
```

`mysqli_real_escape_string` is there but it only protects against SQL injection by escaping quotes for the database query. It does nothing against XSS. The HTML special characters go into the database untouched and come back out as executable code.

---

## Medium Security

Medium adds different filtering to each field. This is where it gets interesting because the developer focused all the security on the obvious target (the Message field) and left the Name field weak.

**Message field:**

```php
$message = strip_tags(addslashes($message));
$message = htmlspecialchars($message);
```

Three functions stacked: `addslashes()` escapes quotes, `strip_tags()` removes all HTML tags, and `htmlspecialchars()` encodes special characters. This is locked down. Nothing gets through.

**Name field:**

```php
$name = str_replace('<script>', '', $name);
```

Just `str_replace` looking for the exact string `<script>`. Same weak filter as Reflected XSS Medium.

### The Bypass

Attack the Name field. Same two options as Reflected XSS Medium:

**1. Mixed case:**

- Name: `<Script>alert('XSS')</Script>` (after fixing maxlength in DevTools)
- Message: `anything`

**2. Nested tags:**

- Name: `<scr<script>ipt>alert('XSS')</scr<script>ipt>`
- Message: `anything`

Both work because `str_replace` is case sensitive and doesn't do recursive replacement. Remember to increase `maxlength` on the Name field first or the payload gets truncated.

The lesson here is that developers often protect the obvious input (a big text area where users write messages) and overlook the smaller fields (a short name field that "nobody would put code in"). Every input is an attack surface.

---

## High Security

High upgrades the Name field filter to a regex but keeps the Message field locked down the same way.

**Message field:** Still has `strip_tags()`, `addslashes()`, and `htmlspecialchars()`. Still unbreakable.

**Name field:**

```php
$name = preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name);
```

Same regex as Reflected XSS High. The `(.*)` wildcards between each letter of "script" and the `/i` case insensitive flag kill both the mixed case and nested tag bypasses.

### The Bypass

Same approach as Reflected XSS High. Ditch script tags entirely and use an event handler:

**1. Fix maxlength** on the Name field in DevTools.

**2. Enter the payload:**

- Name: `<img src=x onerror=alert('XSS')>`
- Message: `anything`

The regex only filters the word "script". The `<img>` tag with `onerror` doesn't contain "script" anywhere so it passes right through. The browser tries to load the image from `src=x`, fails, and executes the `onerror` handler.

Other payloads that work:

```
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

Always remember to bypass `maxlength` first. The Name field is your only attack vector because Message is fully protected.

---

## Impossible Security

Impossible properly secures both fields:

```php
checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');

$message = stripslashes($message);
$message = htmlspecialchars($message);
$message = ((isset($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string(...) : ...);

$name = stripslashes($name);
$name = htmlspecialchars($name);
$name = ((isset($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string(...) : ...);
```

Three layers:

**1. `htmlspecialchars()` on both fields.** Not just Message this time. Both Name and Message get their special characters encoded. No HTML tag survives in either field.

**2. `mysqli_real_escape_string()` for SQL injection protection.** Escapes special characters before the database query.

**3. Anti CSRF token** via `checkToken()` and `generateSessionToken()`. Prevents attackers from automating submissions or tricking users into posting malicious guestbook entries through CSRF.

The key difference from the other levels: both fields are treated equally. The earlier levels had a mismatch where one field was secured and the other wasn't. Impossible applies the same protection everywhere.

This level is not solvable. It's the reference implementation.

---

## Stored vs Reflected XSS

| | Reflected | Stored |
|---|---|---|
| Persistence | Only in the URL, gone after one request | Saved in database, fires on every page load |
| Attack delivery | Victim must click a crafted link | Attacker injects once, all visitors are victims |
| Impact | One user at a time | Every user who visits the page |
| Detection | Payload visible in the URL | Payload hidden in database, URL looks normal |
| DVWA example | Name echoed back in response | Guestbook entry stored and displayed |

---

## What I Learned

Stored XSS is more dangerous than Reflected because of persistence. One successful injection hits every future visitor. In a real app this could be a forum post, a user profile, a product review, or anything that gets stored and displayed to others. The payload lives in the database until someone manually removes it.

Client side validation is not security. The `maxlength` attribute on the Name field stops nothing. Anyone can open DevTools and change it in two seconds. Or skip the browser entirely with curl. Input length limits must be enforced on the server. The HTML attribute is a UX convenience, not a security control.

Developers tend to protect the obvious inputs and forget the rest. In Medium, the Message field gets three layers of protection while the Name field gets one weak `str_replace`. Every input that touches the database and gets rendered back to users needs the same level of protection. One weak field is all an attacker needs.

The fix is the same as Reflected XSS: `htmlspecialchars()` on output. Don't try to filter dangerous tags. Don't try to blocklist patterns. Just encode everything. Applied consistently to all fields, it stops all XSS regardless of how creative the payload is.

`mysqli_real_escape_string` protects against SQL injection but not XSS. They're different vulnerabilities that require different defenses. Escaping quotes for a SQL query does nothing about `<script>` tags in HTML output. Always apply the right defense for the right context.

*Educational purposes only. Metasploitable2 is a deliberately vulnerable VM.*
