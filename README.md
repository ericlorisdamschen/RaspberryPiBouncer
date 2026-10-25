# Bouncer

A home network ad, tracker and scam blocker for the Raspberry Pi (3 B or newer), built to be set up by people who never touch a command line.

- **Blocks** ads and trackers (HaGeZi Multi NORMAL, "balanced"), scam and malware websites (HaGeZi Threat Intelligence mini + fake shops), and optionally adult content with SafeSearch (family filter).
- **Dashboard** at `http://bouncer.local` in English, German and French, protected by a 4-digit PIN (5 tries, then 15 minutes locked). Dark mode follows sunrise and sunset in Luxembourg.
- **Privacy:** statistics are kept 7 days and never contain website names. Device names are shown; website names are not.
- **Network check:** Bouncer verifies that the router really sends devices to it (IPv4 and IPv6) and shows per device whether it is protected.
- **"A website doesn't work?"**: unblocks what was just blocked on one device, without showing names.
- **Encrypted DNS** to the internet (DNS over TLS via Quad9 and Cloudflare), with automatic fallback.
- **Address mode** for routers that can't change their DNS server (e.g. Orange Livebox).
- **Updates:** block lists weekly; software nightly from signed GitHub releases with automatic rollback; OS security updates automatically.
- **Router guides** (PDF, EN/DE/FR) for the routers common in Luxembourg, downloadable from the dashboard.

See **[INSTALL.md](INSTALL.md)** for setup.

## Layout

```
bouncer/            the application (Python 3, aiohttp, dnslib)
  static/           dashboard (HTML/CSS/JS, translations, router guide PDFs)
system/             systemd services and OS configuration
image/              pi-gen stage that builds the SD card image
.github/workflows/  image build and tests
tools/              keygen, make_release, devserver
docs/router-guide/  source of the router guide PDFs
tests/              automated tests (python3 -m pytest)
install.sh          install on an existing Raspberry Pi OS (for testing)
```

## Licences

Bouncer downloads the HaGeZi DNS block lists (GPL-3.0, https://github.com/hagezi/dns-blocklists) at runtime and includes a copy in the SD card image.
