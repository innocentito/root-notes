# DVWA XSS Reflected – Metasploitable2

**Target:** Metasploitable2 
**Attacker:** Kali Linux
**Category:** Cross Site Scripting (Reflected)
**App:** DVWA (Damn Vulnerable Web Application)

---

## How It Works

Reflected XSS happens when a web app takes user input and immediately echoes it back into the page without sanitizing it. The input isn't stored anywhere. It only appears in the response to that one request. The classic attack vector is a crafted URL that contains the payload as a parameter. You send that link to someone, they click it, and the script runs in their browser in the context of the vulnerable site.

DVWA's Reflected XSS page has a simple form with a name field. You type your name, submit it, and the page says "Hello [your name]". The question is what happens when your "name" contains HTML or JavaScript.

---

## Low Security

No filtering at all. Whatever you type goes straight into the HTML response.

**1. Set DVWA Security to Low.**

**2. Enter this in the name field:**

```
<script>alert('XSS')</script>
```

**3. Submit.** The page renders:

```html
<pre>Hello <script>alert('XSS')</script></pre>
```

The browser sees a valid script tag and executes it. Alert pops up.

This works because the PHP code does absolutely nothing to the input:

```php
$name = $_GET['name'];
echo "<pre>Hello {$name}</pre>";
```

Raw `$_GET` straight into `echo`. That's about as vulnerable as it gets.

---

## Medium Security

Medium adds a filter using `str_replace`:

```php
$name = str_replace('<script>', '', $_GET['name']);
```

This removes every occurrence of `<script>` from the input. So the basic payload gets stripped and you just see `alert('XSS')` as plain text on the page.

### The Bypass

`str_replace` in PHP has two weaknesses.

**1. Case sensitivity.** It only matches the exact string `<script>` in lowercase. Mixed case goes right through:

```
<Script>alert('XSS')</Script>
```

Other variations that work:

```
<SCRIPT>alert('XSS')</SCRIPT>
<sCrIpT>alert('XSS')</sCrIpT>
```

**2. No recursive replacement.** It only does one pass. You can nest the tag so that removing the inner `<script>` creates a new one:

```
<scr<script>ipt>alert('XSS')</scr<script>ipt>
```

The filter removes the inner `<script>` tags and whats left is `<script>alert('XSS')</script>`. The easiest bypass is just using mixed case though.

---

## High Security

High replaces `str_replace` with `preg_replace` and a regex:

```php
$name = preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET['name']);
```

Breaking down this regex:

- `<` matches a literal opening bracket
- `(.*)` between every letter means "any characters in between"
- `s`, `c`, `r`, `i`, `p`, `t` spells out "script" with wildcards between each letter
- `/i` flag makes it case insensitive

This kills both bypasses from Medium. Mixed case gets caught by `/i`. Nested tags get caught by `(.*)` which matches anything between the letters. Doesn't matter how you scramble it, if the letters s, c, r, i, p, t appear in that order after a `<`, it gets stripped.

### The Bypass

Stop using `<script>` entirely. The regex only cares about the word "script". Other HTML elements can execute JavaScript through event handlers:

```
<img src=x onerror=alert('XSS')>
```

How this works: the `<img>` tag tries to load an image from `src=x`. That file doesn't exist, so the browser fires the `onerror` event, which runs your JavaScript. The regex never triggers because there's no "script" anywhere in the payload.

Other payloads that work:

```
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
```

All of these use event handlers instead of script tags. The regex is blind to them.

---

## Impossible Security

Impossible uses a completely different approach:

```php
checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');
$name = htmlspecialchars($_GET['name']);
echo "<pre>Hello {$name}</pre>";
generateSessionToken();
```

Two layers of protection:

**1. `htmlspecialchars()`** converts special characters into HTML entities:

| Character | Becomes |
|-----------|---------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#039;` |
| `&` | `&amp;` |

If you enter `<script>alert('XSS')</script>`, the output is:

```
&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;
```

The browser renders this as visible text on the page. No tag is created, no code is executed. This doesn't try to identify bad input. It just encodes every special character so nothing can ever be interpreted as HTML. No bypasses possible.

**2. Anti CSRF token** with `checkToken()` and `generateSessionToken()`. Every request needs a valid one time token that matches the users session. Even if an attacker crafts a malicious URL, the token won't be valid for the victim's session. And tokens are regenerated on every page load so you can't reuse them.

This level is not meant to be solved. Its the reference implementation showing how to do it properly.

---

## What I Learned

Reflected XSS is the simplest form of XSS but still dangerous. The payload travels through the URL, which means the attacker has to trick someone into clicking a link. Unlike Stored XSS, the payload isn't persistent. But combined with URL shorteners or social engineering, it's still a real threat.

Blocklist filtering is a losing game. Low has no filter. Medium blocks the exact string `<script>`. High blocks all variations of "script" with a regex. Each one gets bypassed because there's always another way to execute JavaScript in HTML. The attacker only has to find one way past the filter. The defender has to block all of them.

`htmlspecialchars()` is the right approach because it doesn't try to recognize dangerous input. It just makes all special characters harmless by encoding them. There's nothing to bypass because the function doesn't care what the input is. Output encoding beats input filtering every time.

Client side security means nothing. The URL parameter is fully controlled by the attacker. Any validation in JavaScript or HTML attributes can be bypassed by editing the URL directly, using curl, or using a proxy like Burp Suite.

CSRF tokens add defense in depth. Even if someone found a way past `htmlspecialchars()` (which they won't), the CSRF token would still prevent an attacker from crafting a working malicious URL for a victim. Multiple layers of security mean one layer failing doesn't compromise the system.

*Educational purposes only. Metasploitable2 is a deliberately vulnerable VM.*
