# Malicious Website Blocker

A lightweight **malicious website blocker** that helps prevent access to known phishing, malware, and scam domains by maintaining a blocklist and applying it to your environment.

> This repository is intended for defensive/security use. Use responsibly.

## What it does

- Maintains a list of domains/URLs considered malicious.
- Provides a simple workflow to **add**, **review**, and **deploy** blocking rules.
- Can be adapted to multiple enforcement points, e.g.:
  - OS hosts file (local blocking)
  - DNS sinkhole / RPZ
  - Browser/extension allow/deny lists
  - Proxy / firewall URL filtering

## Quick start

### 1) Clone

```bash
git clone https://github.com/XNOMOUS-OPS/malicious-website-blocker.git
cd malicious-website-blocker
```

### 2) Create / maintain a blocklist

Create a file such as `blocklist.txt` (one domain per line):

```text
example-malware.com
phishingsite.test
bad-domain.xyz
```

**Tips**
- Prefer **domains** (e.g., `bad.com`) over full URLs when possible.
- Do not include protocols (`http://`, `https://`) unless your enforcement method requires it.
- Comment lines can start with `#`.

### 3) Apply blocking

How you apply blocking depends on where you want enforcement. Common approaches:

#### A) Hosts file (local machine)

Append entries to your hosts file to redirect domains to `0.0.0.0`:

```text
0.0.0.0 example-malware.com
0.0.0.0 bad-domain.xyz
```

> Hosts file locations:
> - Linux/macOS: `/etc/hosts`
> - Windows: `C:\Windows\System32\drivers\etc\hosts`

#### B) DNS sinkhole / RPZ

If you run your own DNS server (e.g., BIND/Unbound/Pi-hole), import the blocklist and configure a sinkhole response.

#### C) Proxy / firewall URL filtering

Many proxies and next-gen firewalls support importing deny lists.

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add or update the blocklist
4. Open a pull request

When submitting domains, include a short reason and a reference (optional but helpful), e.g. threat intel report, phishing screenshot, etc.

## Safety and disclaimers

- Blocking can break legitimate services if domains are misclassified.
- Review changes before deployment.
- This project provides no warranty; use at your own risk.

## License

Add a license file (e.g., MIT, Apache-2.0, GPL-3.0) to clarify usage.
