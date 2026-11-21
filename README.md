# cyberrakshak/monitor

Cyber Rakshak error monitoring for **PHP 8.1+**: what goes wrong in your site or script lands on your site's **Errors**
page in the Cyber Rakshak console, scrubbed of secrets before it leaves. One class (`CyberRakshak\Monitor`), no
dependencies; curl when it is there, PHP's own streams when not.

## What it catches

- **Uncaught exceptions**: the handler that was there before still runs; without one, PHP's own "Uncaught …" message
  and exit.
- **Fatal errors**, out of memory too (at shutdown). Running out of memory is reported wherever PHP still runs shutdown
  functions after it; Ubuntu's PHP 8.1.34 packages (deb.sury.org) run none, so nothing can report it there.
- With `captureErrors`, **warnings and user errors** (PHP's handling of them is unchanged).
- Anything you report yourself: `captureException($e)` and `captureMessage($text)`.

Everything is sent at the end of the request or script (and as soon as 10 problems wait), with at most 2 s for it, so a
page is never held long.

## Install

```sh
composer require cyberrakshak/monitor
```

## Use

```php
\CyberRakshak\Monitor::init(['key' => getenv('CR_MONITOR_KEY'), 'release' => '2026.11.21', 'environment' => 'production']);
try {
    chargeCard($order);
} catch (\Throwable $e) {
    \CyberRakshak\Monitor::captureException($e, ['route' => 'checkout', 'context' => ['step' => 2]]);
}
```

The key is your site's app key (`crk_…`), made on the site's **Security scan** tab: under **Apps, servers and scripts**, press **Make an app key**. Composer's autoloader loads the class.

Laravel: in `AppServiceProvider::boot()`,
`\CyberRakshak\Monitor::init(['key' => config('services.cyberrakshak.key'), 'environment' => app()->environment(), 'handleExceptions' => false]);`
and in `bootstrap/app.php`,
`->withExceptions(fn ($e) => $e->report(fn (Throwable $t) => \CyberRakshak\Monitor::captureException($t)))`.
The route is then Laravel's (`GET /orders/{order}`).

## Options (`init([...])`)

| Option | Meaning |
|---|---|
| `key` | Your site's app key, `crk_` and 32 letters or digits. Required; with no valid key the library does nothing. |
| `endpoint` | Where reports go. Default `https://app.cyberrakshak.ai/api/v1/app-reports`. |
| `release` | Your version or build (`A-Z a-z 0-9 . _ + -`, at most 60), so a problem shows the release it started in. |
| `environment` | `production`, `staging`… (`a-z 0-9 _ -`, at most 30). |
| `enabled` | `false` sends nothing (default `true`). |
| `sampleRate` | 0 to 1: the share of problems sent (default 1, all). |
| `beforeSend` | A callable that gets each problem (an array), already scrubbed; return it (changed if you like) or `null` to drop it. |
| `debug` | Says on standard error (or the error log) what the library does and why something was not sent. The key is never printed. |
| `context` | Values sent with every problem: at most 20, strings (300 characters), numbers, true/false. |
| `scrubNames` | Names of your own whose values are removed, like `password=`: whole words, `A-Z a-z 0-9 _ . -`, at most 50. Only adds to the built-in rules. |
| `scrubPatterns` | PCRE patterns of your own, with their delimiters (`'/faces\/\S+/'`): what they match becomes `[removed]`. At most 20; one that does not compile, or matches an empty text, is left out. Only adds to the built-in rules. |
| `platform` | `server` (the default), `script`, `desktop`, `mobile` or `other`. |
| `handleExceptions` | Install an exception handler (default `true`; `false` when your framework reports, as Laravel does). |
| `captureErrors` | Also report warnings and user errors (default `false`). |
| `spool` | Where what could not be sent waits for a later request: `true` (the temp folder, the default), a folder, or `false` (nowhere). |

Methods: `Monitor::init()`, `captureException($e, ['route' => …, 'context' => […], 'level' => …])`,
`captureMessage($text, ['level' => 'warning', 'route' => …, 'context' => […]])`, `flush($timeout = 2.0)` (`true` when
nothing is left waiting), `scrub($text)` (shows what a text would become), `close()`.

## What is sent, and what never is

Sent, per problem: its kind (exception, crash, log message), its message, where it was thrown and its trace (file, line
and function; never the arguments), the route or command (never its query string), the level, how many times it
happened and when last; with each request: the library's name and version, `php` and its version, your release and
environment.

Never sent: request or response bodies, headers, cookies, sessions, form fields, environment variables.

**Scrubbed before anything leaves**: query strings; `Bearer`/`Basic` values; the value after `password`, `secret`,
`token`, `api_key` and the like; JSON Web Tokens; keys that say what they are (`crk_`, `sk_live_`, `ghp_`, `AKIA`…);
email addresses; IBANs (mod-97 checked); card numbers (Luhn-checked); the value after `pin`, `otp`, `cvv`, `iban`,
`sort_code`, `card_number`, `account_number`, `cookie`, `signature`, `authorization` and the like, as whole words only
(`company:` and `spinning:` stay); long hex and random-looking runs. They become `[removed]`, `[token]`, `[email]`,
`[iban]` or `[card]`, and a context entry whose name is one of these names is sent as `[removed]`. `scrubNames` and
`scrubPatterns` add names and patterns of your own; nothing switches the built-in rules off. The console scrubs
everything again when it arrives.

At most 10 problems go per request, each request under 64 KB; repeats of one problem are counted, not resent; `429`,
`5xx` and no answer are kept (in a small file in the temp folder) and tried again later, never before `Retry-After`.
Nothing in the library throws into your code.

Full documentation, the same library for other platforms, and every file's SHA-256:
**https://app.cyberrakshak.ai/sdk/README.md**

## Development

```sh
composer install
composer test                 # tests/run.php, the class loaded by vendor/autoload.php
php -n tests/run.php          # the same with no php.ini: no curl, no mbstring
```

The tests talk to `tests/fake-server.mjs` (Node.js 18+), on 127.0.0.1 only: no test talks to a real Cyber Rakshak host.
`src/CyberRakshakMonitor.php`, `LICENSE` and the two test fixtures are byte for byte the ones served at
https://app.cyberrakshak.ai/sdk/ and are not edited here: they are changed in the Cyber Rakshak console's repository and
copied by its `scripts/sdk-packages.mjs`.

## For maintainers

There is no publish workflow: **Packagist reads this GitHub repository**. composer.json has no `version`: each git tag
`vX.Y.Z` is a version. A release: copy the new file in, add the CHANGELOG entry, commit, tag `vX.Y.Z`, push the tag.

Once, on packagist.org (signed in with GitHub, as the account that will own the `cyberrakshak` vendor name): Submit
(https://packagist.org/packages/submit) the repository URL
`https://github.com/LaabamOne-Business-Solutions-Pvt-Ltd/cyberrakshak-monitor-php`. Packagist then updates itself on
every push through its GitHub hook; if the package page says it is not auto-updated, add the hook by hand in this
repository's Settings → Webhooks: payload URL `https://packagist.org/api/github?username=<packagist username>`, content
type `application/json`, secret = that Packagist account's API token, just the push event.

## Licence

MIT. Copyright (c) 2026 Laabam One Business Solutions (OPC) Private Limited. See [LICENSE](LICENSE).
