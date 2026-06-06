# Ateculus Security — Changelog

## 1.1.0

### Bug Fixes
- Direct access to `/wp-login.php` without the gate cookie now redirects to the homepage (302) instead of returning a 503 error
- Direct access to `/wp-admin` without the gate cookie now redirects to the homepage instead of triggering a server error
- Cloudflare detection now correctly handles servers running the Nginx or Apache `real_ip` module — when the web server has already replaced `REMOTE_ADDR` with the real visitor IP via `CF-Connecting-IP`, Cloudflare is now detected via header matching rather than IP range checking

### New Features

#### 404 Flood Protection
- Tracks 404 hits per IP in a new `wp_asec_404s` database table
- Bans IPs that exceed a configurable number of 404s within a configurable time window (default: 20 hits / 10 minutes)
- Instant-ban for requests to known credential and exploit paths: `.aws/credentials`, `.ssh/id_rsa`, `.env`, `docker-compose`, `_ignition/execute-solution`, `actuator/`, and many more
- Both modes are independently toggleable from the Settings tab

#### Security Headers
- Sends security headers on every response (frontend, admin, and login page): `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Strict-Transport-Security` is added automatically when the site is running on HTTPS
- Can be disabled from the Security Hardening section

#### Login Honeypot
- Adds a hidden field to the login form that real users never see or interact with
- Any IP that submits a value in that field is immediately banned
- Returns a generic "incorrect username or password" error so bots get no useful signal
- Can be disabled from the Login Protection section

#### Email Alerts
- Sends an email to the admin whenever an IP is banned, including the IP address, ban reason, attempt count, timestamp, and a direct link to the Banned IPs tab
- Covers all ban reasons: brute force, bad bot, scan probe, 404 flood, and honeypot
- Alert email address is configurable; defaults to the WordPress site admin email
- Disabled by default to prevent noise before the whitelist is configured

#### Disable File Editing
- Adds a checkbox to define `DISALLOW_FILE_EDIT` from the plugin, removing the Theme Editor and Plugin Editor menus from wp-admin
- Does not require editing `wp-config.php`
- Detects and notes if the constant is already set in `wp-config.php`

#### Login Activity Log
- Records every successful login: username, IP address, and timestamp
- Stored in a new `wp_asec_logins` table, retained for 90 days, purged by the existing hourly cron
- New Login Log tab in the admin shows the 200 most recent entries with a quick Ban IP button on each row
- Useful for spotting account takeovers from unfamiliar IPs

#### Configurable Login Token Duration
- The gate cookie that grants access to the hidden login URL was previously hardcoded at 7 days
- Now configurable in the Hidden Login URL settings section (1–365 days)
- The cookie refreshes its expiry on every visit to the custom slug

#### Cloudflare IP Auto-Sync
- Cloudflare IP ranges (IPv4 and IPv6) are no longer hardcoded — they are fetched from Cloudflare's official published endpoints: `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`
- Ranges are fetched on plugin activation and refreshed automatically every 24 hours via WP-Cron
- Falls back to built-in defaults if the fetch fails, so detection never breaks
- A "Refresh Now" button is available in the Help tab for manual updates
- Settings tab shows when the ranges were last synced

#### Cloudflare IPv6 Detection
- Added Cloudflare's published IPv6 ranges to the IP detection logic
- Added IPv6 CIDR matching (`ip6_in_cidr`) to support checking IPv6 addresses against IPv6 CIDR notation

#### New Admin Tabs
- **404 Log** — shows the last 300 individual 404 hits with IP, URL, timestamp, and a Ban IP button
- **Login Log** — shows the last 200 successful logins with username, IP, timestamp, and a Ban IP button
- **Help** — documentation covering Cloudflare setup (Nginx and Apache configs), how the hidden login URL works, whitelist guidance, WP-Cron setup, and lockout recovery instructions

#### Admin Improvements
- Your IP in the Settings tab now shows whether it is IPv4 or IPv6
- A note is shown when connected via IPv6 suggesting you also whitelist your IPv4 address
- Cloudflare status bar shows when the IP ranges were last synced from Cloudflare
- The Help tab's Nginx and Apache config snippets are generated from the live cached ranges rather than hardcoded, so copy-pasted configs are always current
- Banned IPs tab now shows reason labels for all ban types: Brute Force, Bad Bot, Scan Probe, 404 Flood, Honeypot, Manual Ban

### Database Changes
- Added `wp_asec_404s` table (ip, uri, hit_at) — auto-created on first load via `maybe_upgrade()` for existing installs
- Added `wp_asec_logins` table (ip, username, logged_at) — auto-created on first load via `maybe_upgrade()` for existing installs
- DB version bumped to 1.2

---

## 1.0.0 — Initial Release

- Brute-force login protection: tracks failed logins per IP and bans after a configurable number of attempts within a rolling time window
- IP banning with configurable duration (hours), permanent ban option, and manual ban/unban from the admin
- Block scope setting: restrict bans to wp-admin and wp-login only, or apply to the entire site
- XML-RPC blocking: disables XML-RPC entirely and removes the X-Pingback header
- User enumeration blocking: blocks `?author=` scans that expose WordPress usernames
- WordPress version hiding: removes the version number from page source and RSS feeds
- Bad bot auto-banning: detects and bans IPs using known scanner user agents (sqlmap, Nikto, Nmap, Nuclei, Masscan, Burp Suite, etc.)
- REST API restriction: optionally blocks REST API access for non-logged-in users
- Hidden login URL: set a custom slug (e.g. `/my-portal/`) that sets a secure HMAC gate cookie and redirects to the real wp-login.php; direct access to wp-login.php and wp-admin without the cookie redirects to the homepage
- Cloudflare support: detects Cloudflare by checking REMOTE_ADDR against Cloudflare's IPv4 ranges; reads the real visitor IP from CF-Connecting-IP to ensure bans target the correct address
- IP whitelist: whitelisted IPs bypass all blocking and banning rules
- Custom ban message for blocked visitors
- Admin UI with three tabs: Settings, Banned IPs, Attempts Log
- Hourly WP-Cron cleanup: purges login attempts older than 7 days and expired bans older than 30 days
