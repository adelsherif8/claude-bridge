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
