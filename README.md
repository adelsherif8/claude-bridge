# Claude Bridge

REST API bridge for Claude Code on WordPress sites with no SSH access.

- Token-only or Token + Application Password auth
- WAF-safe base64 content transport
- Automatic updates from a private update server (shows in the WordPress Updates screen)

## Install

1. Download the latest zip from [Releases](https://github.com/adelsherif8/claude-bridge/releases).
2. WordPress admin → Plugins → Add New → Upload Plugin.
3. Activate, then go to **Settings → Claude Bridge**.
4. Copy the token. Auto-updates are enabled by default — no configuration needed.

## Changelog

### 1.11.1
- Failed leads in `/entries` carry a short `reason`: the HTTP code and the message
  GoHighLevel sent back, in plain words for the common cases (invalid email or phone).
  Never the raw payload.

### 1.11.0
- `GET /analytics/funnel` takes `offset` (days back), so the dashboard can compare a period
  with the one before it.
- It also returns lead breakdowns, counted on the site: by source (Google Ads, Facebook /
  Instagram, Microsoft Ads, other campaigns, direct / organic, worked out from `gclid`,
  `fbclid`, `msclkid` and UTM tags), top UTM campaigns, form, weekday and hour. Counts only.
- New `GET /entries?days=&page=&per_page=&q=&status=&form=`: the actual leads from whichever
  form plugin the site runs, newest first, searchable by name/email/phone and filterable by
  delivery status and form. Includes source and campaign; never IP addresses or raw GHL
  payloads.

### 1.10.0
- New `GET /plugins` and `POST /plugins/update`: update Adel's own plugins (Contact Form +
  GoHighLevel, CFT Group Forms, AutoShippers Forms) to the version their own updater offers.
  Matched by plugin name AND author; never accepts a URL or package.
- Safety: skips a site that's already unhealthy; backs each plugin up as a zip in a locked
  folder; after each update checks the home page actually renders (not just HTTP 200) and
  automatically restores the previous version if it doesn't; stops if a site can't be
  recovered. A plugin folder can never be left missing.

### 1.9.1
- Analytics: a page tracked by URL in older events and by post ID in newer ones is now
  shown once, not twice (e.g. "/" and "Home").
- Analytics: sessions whose events carry no page — form views recorded before page
  tracking existed — are counted under "(not attributed)" instead of being dropped, so
  site totals no longer under-report.

### 1.9.0
- New read-only `GET /analytics/funnel?days=30` for the conversion dashboard: per
  landing page views, form fills, call taps (with unique callers) and conversion,
  plus step drop-off and GoHighLevel delivery health.
- Aggregated in SQL on the site and returned as counts only — no names, emails,
  phone numbers, IP addresses or user agents leave the site.
- Reads whichever form plugin is installed: Contact Form + GHL (`cfg_events`),
  Autoshippers Forms (`as_events`) and CFT Group Forms (`cftg_funnel`), including
  their schemas from before call tracking existed.
- Taps on pages with no form views are reported separately so they never inflate
  the conversion rate.

### 1.8.0
- Updater: cache the release manifest for 12 hours instead of 30 minutes, cutting
  update-server requests per site by roughly 24x. Failed checks still retry after
  30 minutes, so an outage never blocks updates for 12 hours.
- Package download links are now signed for 7 days and quantised to midnight UTC, so a
  cached manifest can never hand WordPress a dead link. The key and signature check are
  unchanged and just as strict.
- "Check again" on the Updates screen still forces a fresh check, bypassing the cache.
- Update server: site heartbeats are written at most once per site per day, or when the
  site's plugin version changes, instead of on every request.
- Update server: the storage SDK is loaded only when a heartbeat is actually written,
  removing that cost from every update check.

## Author

Adel Emad — [adelatya.com](https://adelatya.com) — <adelsherif8@gmail.com>

## License

GPLv2 or later
