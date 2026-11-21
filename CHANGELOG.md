# Changelog

## [1.0.0] - 2026-11-21

First release on Packagist: the PHP library served at https://app.cyberrakshak.ai/sdk/php/ since 2026-11-21, as the
class `CyberRakshak\Monitor` (autoloaded by Composer).

- Reports uncaught exceptions (the previous handler still runs), fatal errors (out of memory too) and, with
  `captureErrors`, warnings and user errors.
- `init`, `captureException`, `captureMessage`, `flush`, `scrub`, `close`; options `key`, `endpoint`, `release`,
  `environment`, `enabled`, `sampleRate`, `beforeSend`, `debug`, `context`, `platform`, `handleExceptions`,
  `captureErrors`, `spool`.
- Secrets scrubbed before anything leaves, by the rules every Cyber Rakshak library shares. curl when it is there,
  PHP's own streams when not.
