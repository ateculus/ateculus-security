# Ateculus Security

A lightweight WordPress security plugin providing brute-force protection, IP banning, bad bot filtering, and security hardening — with no cloud dependencies.

## Features

### Active Protection
- **Brute-force protection** — bans IPs after a configurable number of failed logins within a rolling time window
- **Automatic IP banning** — six ban triggers: brute force, bad bot, scan probe, 404 flood, honeypot, and manual
- **Bad bot detection** — instantly bans SQLMap, Nikto, Nmap, Burp Suite, Nuclei, and dozens of other known scanning tools by user-agent
- **404 flood protection** — rate-limits 404-heavy IPs and instantly bans requests to credential paths (`.env`, `.aws/credentials`, `docker-compose`, etc.)
- **Login honeypot** — hidden field on the login form catches bots that auto-fill every input
- **Whole-site IP blocking** — block any IP from accessing the entire site

### Hidden Login URL
- Replace `/wp-login.php` with a custom slug
- Sets a secure HMAC gate cookie on the custom slug; direct access to `wp-login.php` and `wp-admin` without the cookie redirects silently to the homepage

### Security Hardening
- XML-RPC fully disabled (removes X-Pingback header too)
- User enumeration blocked (`?author=` queries)
- WordPress version hidden from page source, feeds, and meta tags
- REST API optionally restricted to authenticated users
- File editing disabled in wp-admin (`DISALLOW_FILE_EDIT`)
- Security headers on all frontend, admin, and login pages:
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
  - `Strict-Transport-Security` (HTTPS sites only)

### Cloudflare Support
- Auto-detects real visitor IP behind Cloudflare proxy
- Cloudflare IP ranges fetched at activation and refreshed every 24 hours
- Manual refresh button in the Help tab

### Admin Visibility
- **Banned IPs** — view, manually ban, and unban with one click
- **Attempts log** — failed logins grouped by IP with count and last attempt time
- **404 log** — last 300 individual 404 hits with IP, URL, and timestamp
- **Login log** — every successful login recorded with username, IP, and timestamp (90-day retention)
- **Email ban alerts** — get notified whenever an IP is banned

## Requirements

- WordPress 6.0+
- PHP 8.0+

## Installation

1. Download the latest ZIP from the [Releases](../../releases) page
2. Go to **Plugins → Add New → Upload Plugin** in your WordPress admin
3. Upload the ZIP and click **Activate Plugin**

## Cloudflare Setup

If your site is behind Cloudflare, add this to your Nginx config so WordPress sees the real visitor IP:

```nginx
real_ip_header CF-Connecting-IP;
```

Or for Apache, add to `.htaccess`:

```apache
RemoteIPHeader CF-Connecting-IP
```

The current Cloudflare IP ranges to whitelist are shown in the **Help** tab of the plugin settings.

## Lockout Recovery

If you lock yourself out by forgetting your custom login URL:

1. Connect to your server via SSH or FTP
2. Open `wp-config.php` and add: `define( 'ASEC_DISABLE_LOGIN_URL', true );`
3. Visit `/wp-login.php` to log in normally
4. Remove the line from `wp-config.php` once logged in

## License

Free for personal use. Commercial use requires written authorization — see [LICENSE](LICENSE) for full terms.

## Author

Built by [Ateculus](https://ateculus.com)
