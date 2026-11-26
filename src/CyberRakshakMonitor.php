<?php

/**
 * Cyber Rakshak error monitoring for PHP, version 1.1.1
 * Docs: https://app.cyberrakshak.ai/sdk/README.md
 * Copyright Laabam One Business Solutions (OPC) Private Limited
 * Released under the MIT licence: https://app.cyberrakshak.ai/sdk/LICENSE
 *
 * One file, no dependencies, PHP 8.1 or later (curl when it is there, PHP's own streams when not). Sends what goes
 * wrong in your site or script to its own Errors page in the Cyber Rakshak console: the exception's text, where it
 * was thrown and its trace (file, line and function, never the arguments), the route or command, when and how often.
 * Secrets are scrubbed here before anything leaves (email addresses, tokens and keys, password=... values, query
 * strings, card numbers); request bodies, headers, cookies, sessions and environment variables are never read.
 *
 *   require_once __DIR__.'/CyberRakshakMonitor.php';     // or list it under "autoload": {"files": [...]} in composer.json
 *
 *   \CyberRakshak\Monitor::init(['key' => getenv('CR_MONITOR_KEY'), 'release' => '2026.11.21', 'environment' => 'production']);
 *   \CyberRakshak\Monitor::captureException($e, ['route' => 'nightly-import', 'context' => ['batch' => 42]]);
 *   \CyberRakshak\Monitor::captureMessage('Payment provider answered slowly', ['level' => 'warning']);
 *
 * Caught by itself: uncaught exceptions (the handler that was there before still runs; without one, PHP's own
 * "Uncaught ..." message and exit), fatal errors (at shutdown), and, with 'captureErrors' => true, warnings and user
 * errors (PHP's handling of them is unchanged). Everything is sent at the end of the request or script (and as soon as
 * 10 problems wait), with at most 2 s for it, so a page is never held long. When the console asks to wait (429) or
 * cannot be reached, problems are kept in a small file in the temp folder and sent by a later request.
 *
 * Laravel: in AppServiceProvider::boot(),
 *   \CyberRakshak\Monitor::init(['key' => config('services.cyberrakshak.key'), 'environment' => app()->environment(), 'handleExceptions' => false]);
 * and in bootstrap/app.php (Laravel reports through its own handler, which this joins):
 *   ->withExceptions(fn ($e) => $e->report(fn (Throwable $t) => \CyberRakshak\Monitor::captureException($t)))
 * The route is then Laravel's (GET /orders/{order}).
 *
 * Nothing in here may throw into your code or slow it: a monitor that fails must never become the site's second problem.
 */

declare(strict_types=1);

namespace CyberRakshak;

final class Monitor
{
    public const VERSION = '1.1.1';

    public const DEFAULT_ENDPOINT = 'https://app.cyberrakshak.ai/api/v1/app-reports';

    private const SDK_NAME = 'cyberrakshak-php';

    private const KINDS = ['exception', 'crash', 'promise', 'log', 'http', 'script'];

    private const PLATFORMS = ['mobile', 'server', 'script', 'desktop', 'other'];

    private const MAX_BATCH = 10;

    private const MAX_WAITING = 50;

    private const MAX_MESSAGE = 4000;

    private const MAX_STACK = 16000;

    private const MAX_ROUTE = 200;

    private const MAX_CONTEXT = 20;

    private const MAX_CONTEXT_KEY = 40;

    private const MAX_CONTEXT_VALUE = 300;

    private const MAX_COUNT = 100000;

    private const MAX_FRAMES = 100;

    private const BODY_LIMIT = 60000;

    private const SEND_TIMEOUT = 2.0;

    private const SEND_WHEN_OLDER = 10.0;

    private const BACKOFF_FIRST = 2.0;

    private const BACKOFF_MAX = 300.0;

    private const RETRY_AFTER_MAX = 86400.0;

    private const BLOCKED = 3600.0;

    private const FATAL = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR;

    private const CAPTURED_ERRORS = E_WARNING | E_USER_WARNING | E_USER_ERROR | E_RECOVERABLE_ERROR;

    /** @var array<string, mixed>|null */
    private static ?array $config = null;

    /** @var array<string, array<string, mixed>> fingerprint => problem, oldest first */
    private static array $queue = [];

    private static ?\WeakMap $reported = null;

    /** @var callable|null */
    private static $previousExceptionHandler = null;

    /** @var callable|null */
    private static $previousErrorHandler = null;

    private static ?\Closure $ownExceptionHandler = null;

    private static ?\Closure $ownErrorHandler = null;

    private static bool $handlersSet = false;

    private static bool $shutdownRegistered = false;

    private static bool $crashed = false;

    private static bool $busy = false;

    private static float $oldest = 0.0;

    private static float $notBefore = 0.0;

    private static float $backoff = 0.0;

    private static float $blockedUntil = 0.0;

    /** @var array<int|string, bool> */
    private static array $logged = [];

    private static ?string $reserve = null;

    /**
     * Starts monitoring. Options: key (required, crk_...), endpoint, release, environment, enabled (default true),
     * sampleRate (0..1, default 1), beforeSend (callable: problem array in, array or null out), debug, context (sent with
     * every problem), platform ('server' unless you say 'script', 'desktop' or 'other'), handleExceptions (default
     * true), captureErrors (warnings and user errors, default false), spool (default true: keep what could not be sent
     * in the temp folder; or a folder of your own; false for none), scrubNames (names of your own whose values are
     * removed, like password=) and scrubPatterns (PCRE patterns, with delimiters, whose matches are removed): both only
     * add to the built-in rules, which always run.
     *
     * @param  array<string, mixed>  $options
     */
    public static function init(array $options): void
    {
        try {
            self::close();
            $debug = ! empty($options['debug']);
            if (($options['enabled'] ?? true) === false) {
                return;
            }
            $key = is_string($options['key'] ?? null) ? trim($options['key']) : '';
            if (preg_match('/^crk_[A-Za-z0-9]{32}$/', $key) !== 1) {
                self::say($debug, "not started: key must be its crk_ app key (the console's Apps & websites: Add, then its Set up page)");

                return;
            }
            $endpoint = is_string($options['endpoint'] ?? null) && preg_match('#^https?://\S+$#i', $options['endpoint']) === 1
                ? $options['endpoint'] : self::DEFAULT_ENDPOINT;
            $release = isset($options['release']) && is_scalar($options['release']) ? (string) $options['release'] : null;
            if ($release !== null && preg_match('/^[A-Za-z0-9._+\-]{1,60}$/', $release) !== 1) {
                self::say($debug, 'release left out: it may hold only A-Z a-z 0-9 . _ + - (at most 60)');
                $release = null;
            }
            $environment = isset($options['environment']) && is_scalar($options['environment']) ? strtolower((string) $options['environment']) : null;
            if ($environment !== null && preg_match('/^[a-z0-9_-]{1,30}$/', $environment) !== 1) {
                self::say($debug, 'environment left out: it may hold only a-z 0-9 _ - (at most 30)');
                $environment = null;
            }
            $rate = isset($options['sampleRate']) && is_numeric($options['sampleRate']) ? (float) $options['sampleRate'] : 1.0;
            $names = self::extraNames($options['scrubNames'] ?? null, $debug);
            $alternation = implode('|', array_map(static fn (string $n): string => preg_quote($n, '/'), $names));
            $spool = $options['spool'] ?? true;
            $spoolDir = is_string($spool) && $spool !== '' ? $spool : ($spool === false ? null : sys_get_temp_dir());
            self::$config = [
                'key' => $key,
                'endpoint' => $endpoint,
                'release' => $release,
                'environment' => $environment,
                'sampleRate' => max(0.0, min(1.0, $rate)),
                'beforeSend' => is_callable($options['beforeSend'] ?? null) ? $options['beforeSend'] : null,
                'debug' => $debug,
                'context' => is_array($options['context'] ?? null) ? $options['context'] : [],
                'extraNames' => $names !== [] ? '/(?<![A-Za-z0-9])((?:'.$alternation.')\\\\?["\']?[ ]*[=:][ ]*\\\\?["\']?)[^ \t\r\n&,;"\'<>\\\\]+/i' : null,
                'extraKeys' => $names !== [] ? '/(?:^|[^A-Za-z0-9])(?:'.$alternation.')$/i' : null,
                'extraPatterns' => self::extraPatterns($options['scrubPatterns'] ?? null, $debug),
                'platform' => in_array($options['platform'] ?? null, self::PLATFORMS, true) ? $options['platform'] : 'server',
                'runtime' => 'php '.PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION,
                'transport' => ($options['transport'] ?? null) === 'stream' || ! function_exists('curl_init') ? 'stream' : 'curl',
                'spool' => $spoolDir !== null ? rtrim($spoolDir, '/\\').DIRECTORY_SEPARATOR.'cyberrakshak-monitor-'.substr(hash('sha256', $key."\n".$endpoint), 0, 16).'.json' : null,
            ];
            self::$reported = new \WeakMap;
            // A little memory kept aside: a script that ran out of memory still has some to report that.
            self::$reserve = str_repeat(' ', 32768);
            if (($options['handleExceptions'] ?? true) !== false) {
                self::$ownExceptionHandler = static function (\Throwable $e): void {
                    self::onException($e);
                };
                self::$previousExceptionHandler = set_exception_handler(self::$ownExceptionHandler);
                self::$handlersSet = true;
            }
            if (! empty($options['captureErrors'])) {
                self::$ownErrorHandler = static function (int $level, string $message, string $file = '', int $line = 0): bool {
                    return self::onError($level, $message, $file, $line);
                };
                self::$previousErrorHandler = set_error_handler(self::$ownErrorHandler);
            }
            if (! self::$shutdownRegistered) {
                self::$shutdownRegistered = true;
                // Registered again from inside: this runs after the app's own shutdown functions, which may still report.
                register_shutdown_function(static function (): void {
                    register_shutdown_function(static function (): void {
                        self::onShutdown();
                    });
                });
            }
            self::debug('started: '.self::SDK_NAME.' '.self::VERSION.' reporting to '.$endpoint);
        } catch (\Throwable $e) {
            self::$config = null;
            self::say(! empty($options['debug']), 'not started: '.$e->getMessage());
        }
    }

    /** Stops monitoring and gives back the handlers that were there before. Anything still waiting is forgotten. */
    public static function close(): void
    {
        try {
            // Only when ours is the one in place: a handler the app set after init() stays.
            if (self::$ownExceptionHandler !== null) {
                $current = set_exception_handler(null);
                restore_exception_handler();
                if ($current === self::$ownExceptionHandler) {
                    restore_exception_handler();
                }
            }
            if (self::$ownErrorHandler !== null) {
                $current = set_error_handler(null);
                restore_error_handler();
                if ($current === self::$ownErrorHandler) {
                    restore_error_handler();
                }
            }
        } catch (\Throwable) {
            // Never a second problem.
        }
        self::$config = null;
        self::$queue = [];
        self::$handlersSet = false;
        self::$previousExceptionHandler = null;
        self::$previousErrorHandler = null;
        self::$ownExceptionHandler = null;
        self::$ownErrorHandler = null;
        self::$crashed = false;
        self::$notBefore = 0.0;
        self::$backoff = 0.0;
        self::$blockedUntil = 0.0;
        self::$logged = [];
    }

    /**
     * Reports a Throwable you caught. Options: route, context, level ('error' or 'warning').
     *
     * @param  array<string, mixed>  $options
     */
    public static function captureException(\Throwable $e, array $options = []): void
    {
        try {
            self::capture('exception', $e, $options);
        } catch (\Throwable) {
            // Never a second problem.
        }
    }

    /**
     * Reports a message. Options: level ('warning', the default, or 'error'), route, context.
     *
     * @param  array<string, mixed>  $options
     */
    public static function captureMessage(mixed $text, array $options = []): void
    {
        try {
            $options['message'] = self::text($text) ?? get_debug_type($text);
            $options['stack'] = null;
            self::capture('log', null, $options);
        } catch (\Throwable) {
            // Never a second problem.
        }
    }

    /** Sends what is waiting now, in at most $timeout seconds. True when nothing is left waiting. */
    public static function flush(float $timeout = 2.0): bool
    {
        try {
            if (self::$config === null) {
                return true;
            }
            self::transmit(microtime(true) + max(0.1, $timeout));

            return self::$queue === [];
        } catch (\Throwable $e) {
            self::debug('flush: '.$e->getMessage());

            return false;
        }
    }

    /**
     * What a text looks like once scrubbed: what this library would send. The built-in rules always run, first; then the
     * names and patterns given to init() as scrubNames and scrubPatterns, which can only add to them.
     */
    public static function scrub(mixed $text): string
    {
        try {
            $out = is_string($text) ? $text : (is_scalar($text) ? (string) $text : '');
            foreach (self::rules() as [$pattern, $replace]) {
                $next = preg_replace_callback($pattern, $replace, $out);
                if ($next === null) {
                    return '[removed]';
                }
                $out = $next;
            }
            $config = self::$config;
            if ($config !== null && $config['extraNames'] !== null) {
                $next = preg_replace_callback($config['extraNames'], static fn (array $m): string => $m[1].'[removed]', $out);
                if ($next === null) {
                    return '[removed]';
                }
                $out = $next;
            }
            foreach ($config['extraPatterns'] ?? [] as $pattern) {
                // A pattern of yours that fails is skipped; the built-in rules have run.
                $next = @preg_replace($pattern, '[removed]', $out);
                if (is_string($next)) {
                    $out = $next;
                }
            }

            return $out;
        } catch (\Throwable) {
            return '';
        }
    }

    /** ISO 13616: the first four characters moved to the end, letters as 10..35, the whole number mod 97 is 1. */
    private static function ibanOk(string $text): bool
    {
        $s = str_replace(' ', '', $text);
        $length = strlen($s);
        if ($length < 15 || $length > 34) {
            return false;
        }
        $moved = substr($s, 4).substr($s, 0, 4);
        $rest = 0;
        for ($i = 0; $i < $length; $i++) {
            $c = ord($moved[$i]);
            $v = $c >= 65 ? $c - 55 : $c - 48;
            $rest = $v > 9 ? ($rest * 100 + $v) % 97 : ($rest * 10 + $v) % 97;
        }

        return $rest === 1;
    }

    /**
     * A context entry's name that says its value is a secret: the words of the password rule anywhere in it, or one of
     * the whole-word names (at the end, not right after a letter or digit: user_pin, x-tink-signature, not spinning).
     */
    private static function secretName(string $name): bool
    {
        if (preg_match('/password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|session[_-]?id/i', $name) === 1
            || preg_match('/(?:^|[^A-Za-z0-9])(?:authorization|cookie|signature|otp|pin|cvv|cvc|iban|bban|pan|account[_-]?(?:no|number|num)|sort[_-]?code|card[_-]?number|bank[_-]?auth[_-]?id)$/i', $name) === 1) {
            return true;
        }
        $keys = self::$config['extraKeys'] ?? null;

        return $keys !== null && preg_match($keys, $name) === 1;
    }

    /**
     * scrubNames: names of your own, as whole words, their values removed like the built-in ones; at most 50.
     *
     * @return list<string>
     */
    private static function extraNames(mixed $list, bool $debug): array
    {
        $names = [];
        if ($list === null) {
            return $names;
        }
        if (! is_array($list)) {
            self::say($debug, 'scrubNames left out: it must be a list of names');

            return $names;
        }
        foreach ($list as $name) {
            if (! is_string($name) || preg_match('/^[A-Za-z0-9_.-]{1,40}$/', $name) !== 1) {
                self::say($debug, 'scrubNames: a name was left out: only A-Z a-z 0-9 _ . - (1 to 40)');

                continue;
            }
            if (count($names) >= 50) {
                self::say($debug, 'scrubNames: only the first 50 are used');

                break;
            }
            if (! in_array(strtolower($name), $names, true)) {
                $names[] = strtolower($name);
            }
        }

        return $names;
    }

    /**
     * scrubPatterns: PCRE patterns of your own, with their delimiters ('/faces\/\S+/'); what they match goes. At most 20;
     * one that does not compile, or matches an empty text, is left out.
     *
     * @return list<string>
     */
    private static function extraPatterns(mixed $list, bool $debug): array
    {
        $patterns = [];
        if ($list === null) {
            return $patterns;
        }
        if (! is_array($list)) {
            self::say($debug, 'scrubPatterns left out: it must be a list of patterns');

            return $patterns;
        }
        foreach ($list as $pattern) {
            if (count($patterns) >= 20) {
                self::say($debug, 'scrubPatterns: only the first 20 are used');

                break;
            }
            if (! is_string($pattern)) {
                self::say($debug, 'scrubPatterns: a pattern was left out: it must be a string');

                continue;
            }
            set_error_handler(static fn (): bool => true);
            try {
                $matched = preg_match($pattern, '');
            } finally {
                restore_error_handler();
            }
            if ($matched === false) {
                self::say($debug, 'scrubPatterns: a pattern was left out: it does not compile');

                continue;
            }
            if ($matched === 1) {
                self::say($debug, 'scrubPatterns: a pattern that matches an empty text was left out');

                continue;
            }
            $patterns[] = $pattern;
        }

        return $patterns;
    }

    // ── Scrubbing: the same rules, in the same order, in every Cyber Rakshak library ──────────────────────────────────

    /** @return list<array{0: string, 1: callable}> */
    private static function rules(): array
    {
        static $rules = null;
        if ($rules !== null) {
            return $rules;
        }
        $kept = static fn (array $m): string => $m[0];

        return $rules = [
            // A query string: ?name=... up to a space or quote. Where a request went is kept, never what it asked.
            ['/\?[A-Za-z0-9_.%-]+[=&][^ \t\r\n#"\'<>]*/', static fn (array $m): string => ''],
            // Authorization values.
            ['/(bearer|basic) +([A-Za-z0-9._~+\/=-]{8,})/i', static fn (array $m): string => preg_match('/[0-9A-Z._~+\/=]/', $m[2]) === 1 ? $m[1].' [token]' : $m[0]],
            // password=..., "client_secret": "...", x-api-key: ... (the name is kept, the value is not). The match starts at
            // the word (what comes before it is kept as it is) and allows 40 more name characters after it.
            ['/((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|session[_-]?id)[A-Za-z0-9_-]{0,40}\\\\?["\']?[ ]*[=:][ ]*\\\\?["\']?)[^ \t\r\n&,;"\'<>\\\\]+/i', static fn (array $m): string => $m[1].'[removed]'],
            // JSON Web Tokens (a header of at most 500 characters).
            ['/eyJ[A-Za-z0-9_-]{1,500}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?/', static fn (array $m): string => '[token]'],
            // Keys that say what they are.
            ['/(?<![A-Za-z0-9])(?:crk_|crw_|sk_live_|sk_test_|pk_live_|pk_test_|rk_live_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xoxb-|xoxp-|xoxa-|AKIA|ASIA|AIza)[A-Za-z0-9_-]{10,}/', static fn (array $m): string => '[token]'],
            // Email addresses (at most 64 characters before the @, as in an address).
            ['/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/', static fn (array $m): string => '[email]'],
            // IBANs: two capital letters, two digits, then 11 to 30 capitals or digits (or the same in groups of four, single
            // spaces between), 15 to 34 in all, passing the ISO 13616 mod-97 check. Before cards: an IBAN holds a digit run.
            ['/(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)(?![A-Za-z0-9])/', static fn (array $m): string => self::ibanOk($m[0]) ? '[iban]' : $m[0]],
            // Card numbers: 13 to 19 digits (single spaces or dashes between) that pass the Luhn check.
            ['/(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}/', static fn (array $m): string => self::luhn(str_replace([' ', '-'], '', $m[0])) ? '[card]' : $m[0]],
            // pin: 1234, "iban": "...", set-cookie: ..., x-tink-signature=...: these names only as whole words (not right after a
            // letter or digit, the separator right after the name), so company:, spinning: and japan: stay; the value goes as in
            // the password rule. After IBANs and cards, so a value with spaces in it has gone whole already. A value that is
            // Bearer or Basic and a space was handled above.
            ['/(?<![A-Za-z0-9])((?:authorization|cookie|signature|otp|pin|cvv|cvc|iban|bban|pan|account[_-]?(?:no|number|num)|sort[_-]?code|card[_-]?number|bank[_-]?auth[_-]?id)\\\\?["\']?[ ]*[=:][ ]*\\\\?["\']?)(?!(?:bearer|basic) )[^ \t\r\n&,;"\'<>\\\\]+/i', static fn (array $m): string => $m[1].'[removed]'],
            // Long hex runs: session ids, hashes, keys.
            ['/[0-9a-fA-F]{32,}/', static fn (array $m): string => '[token]'],
            // Long random-looking runs: a digit, an upper-case and a lower-case letter in 40 or more of A-Z a-z 0-9 + _ -.
            ['/[A-Za-z0-9+_-]{40,}/', static fn (array $m): string => preg_match('/[0-9]/', $m[0]) === 1 && preg_match('/[A-Z]/', $m[0]) === 1 && preg_match('/[a-z]/', $m[0]) === 1 ? '[token]' : $kept($m)],
        ];
    }

    private static function luhn(string $digits): bool
    {
        $sum = 0;
        $double = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = ord($digits[$i]) - 48;
            if ($double) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $double = ! $double;
        }

        return $sum % 10 === 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────────────────────────

    /**
     * Valid UTF-8 (anything else becomes U+FFFD), at most $max characters; with or without mbstring. (Not mb_scrub:
     * it puts the app's mb_substitute_character, '?' by default, which would read as a query string.)
     */
    private static function clip(string $text, int $max): string
    {
        if (preg_match('//u', $text) !== 1) {
            $text = htmlspecialchars_decode(htmlspecialchars($text, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8'), ENT_NOQUOTES);
        }
        if (strlen($text) <= $max) {
            return $text;
        }
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, $max, 'UTF-8');
        }

        return preg_match('/^.{0,'.min($max, 65535).'}/us', $text, $m) === 1 ? $m[0] : '';
    }

    /** A scalar as text, without the warning PHP 8.5 gives for NAN or INF as a string; null for anything else. */
    private static function text(mixed $value): ?string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_float($value) && ! is_finite($value)) {
            return is_nan($value) ? 'NAN' : ($value > 0 ? 'INF' : '-INF');
        }

        return is_int($value) || is_float($value) || is_bool($value) ? (string) $value : null;
    }

    private static function length(string $text): int
    {
        return function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : (int) preg_match_all('/./us', $text);
    }

    private static function clean(string $text, int $max): string
    {
        return self::clip(self::scrub(self::clip($text, $max * 2)), $max);
    }

    private static function describe(\Throwable $e): string
    {
        $message = $e->getMessage();

        return $message !== '' ? get_class($e).': '.$message : get_class($e);
    }

    /** The trace: file, line and function of each frame, never the arguments (they can hold anything). */
    private static function stackOf(\Throwable $e): string
    {
        $out = '';
        $depth = 0;
        for ($t = $e; $t !== null && $depth < 4; $t = $t->getPrevious(), $depth++) {
            $out .= ($depth ? "\nCaused by: " : '').self::describe($t).' in '.$t->getFile().':'.$t->getLine();
            $n = 0;
            foreach ($t->getTrace() as $frame) {
                if ($n >= self::MAX_FRAMES) {
                    $out .= "\n#".$n.' …';
                    break;
                }
                $where = isset($frame['file']) ? $frame['file'].'('.($frame['line'] ?? 0).')' : '[internal function]';
                $what = ($frame['class'] ?? '').($frame['type'] ?? '').($frame['function'] ?? '');
                $out .= "\n#".$n.' '.$where.': '.$what.'()';
                $n++;
            }
            $out .= "\n#".$n.' {main}';
        }

        return $out;
    }

    private static function topFrame(?string $stack): string
    {
        if ($stack === null || $stack === '') {
            return '';
        }
        $first = strtok($stack, "\n");

        return is_string($first) && ($at = strrpos($first, ' in ')) !== false ? substr($first, $at + 4) : '';
    }

    /**
     * @param  array<mixed>  ...$sources
     * @return array<string, scalar|null>
     */
    private static function cleanContext(array ...$sources): array
    {
        $out = [];
        foreach ($sources as $source) {
            foreach ($source as $name => $value) {
                $key = self::clip((string) $name, self::MAX_CONTEXT_KEY);
                if (self::secretName((string) $name)) {
                    $value = '[removed]';
                } elseif (is_string($value)) {
                    $value = self::clean($value, self::MAX_CONTEXT_VALUE);
                } elseif (is_float($value) && ! is_finite($value)) {
                    continue;
                } elseif (! is_null($value) && ! is_bool($value) && ! is_int($value) && ! is_float($value)) {
                    continue;
                }
                if (! array_key_exists($key, $out) && count($out) >= self::MAX_CONTEXT) {
                    continue;
                }
                $out[$key] = $value;
            }
        }

        return $out;
    }

    /** A path with its ids taken out: /users/42/orders/9f1c… becomes /users/{id}/orders/{id}. */
    private static function genericPath(string $path): string
    {
        $path = (string) preg_replace('/[?#].*$/s', '', $path);

        return implode('/', array_map(static fn (string $part): string => preg_match('/^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,})$/i', $part) === 1 ? '{id}' : $part, explode('/', $path)));
    }

    /** The route of this request (Laravel's when it is there) or the command of this script. */
    private static function currentRoute(): ?string
    {
        try {
            if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
                $argv = $_SERVER['argv'] ?? [];
                $script = is_array($argv) && isset($argv[0]) && is_string($argv[0]) ? basename($argv[0]) : null;
                if ($script === 'artisan' && isset($argv[1]) && is_string($argv[1]) && preg_match('/^[a-z0-9:_-]+$/i', $argv[1]) === 1) {
                    return 'artisan '.$argv[1];
                }

                return $script;
            }
            $method = is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'].' ' : '';
            if (function_exists('app')) {
                $app = app();
                if (is_object($app) && method_exists($app, 'bound') && $app->bound('router')) {
                    $route = $app->make('router')->current();
                    if (is_object($route) && method_exists($route, 'uri')) {
                        return $method.'/'.ltrim((string) $route->uri(), '/');
                    }
                }
            }
            $uri = $_SERVER['REQUEST_URI'] ?? null;

            return is_string($uri) ? $method.self::genericPath($uri) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private static function nowIso(): string
    {
        $now = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', microtime(true)));

        return $now !== false ? $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z') : gmdate('Y-m-d\TH:i:s\Z');
    }

    private static function say(bool $debug, string $message): void
    {
        if (! $debug) {
            return;
        }
        try {
            if (defined('STDERR')) {
                fwrite(STDERR, '[cyberrakshak-monitor] '.$message."\n");
            } else {
                error_log('[cyberrakshak-monitor] '.$message);
            }
        } catch (\Throwable) {
            // Never a second problem.
        }
    }

    private static function debug(string $message): void
    {
        self::say((bool) (self::$config['debug'] ?? false), $message);
    }

    private static function debugOnce(int|string $id, string $message): void
    {
        if (! isset(self::$logged[$id])) {
            self::$logged[$id] = true;
            self::debug($message);
        }
    }

    // ── Capturing ─────────────────────────────────────────────────────────────────────────────────────────────────────

    /** @param  array<string, mixed>  $options */
    private static function capture(string $kind, ?\Throwable $e, array $options): void
    {
        $config = self::$config;
        if ($config === null || self::$busy) {
            return;
        }
        self::$busy = true;
        try {
            if ($e !== null && self::$reported !== null) {
                if (isset(self::$reported[$e])) {
                    return;
                }
                self::$reported[$e] = true;
            }
            $now = microtime(true);
            if ($now < self::$blockedUntil) {
                return;
            }
            if ($config['sampleRate'] < 1 && ! (mt_rand() / mt_getrandmax() < $config['sampleRate'])) {
                return;
            }
            $message = array_key_exists('message', $options) && is_string($options['message']) ? $options['message'] : ($e !== null ? self::describe($e) : '');
            $stack = array_key_exists('stack', $options) ? $options['stack'] : ($e !== null ? self::stackOf($e) : null);
            $level = $options['level'] ?? null;
            $draft = [
                'kind' => $kind,
                'message' => self::clean($message, self::MAX_MESSAGE),
                'level' => $level === 'error' || $level === 'warning' ? $level : ($kind === 'log' ? 'warning' : 'error'),
                'count' => 1,
                'at' => self::nowIso(),
            ];
            if (trim($draft['message']) === '') {
                $draft['message'] = '(no message)';
            }
            if (is_string($stack) && $stack !== '') {
                $draft['stack'] = self::clean($stack, self::MAX_STACK);
            }
            $route = array_key_exists('route', $options) ? $options['route'] : self::currentRoute();
            $route = self::text($route);
            if ($route !== null && $route !== '') {
                $route = self::clean((string) preg_replace('/[?#].*$/s', '', $route), self::MAX_ROUTE);
                if ($route !== '') {
                    $draft['route'] = $route;
                }
            }
            $context = self::cleanContext($config['context'], is_array($options['context'] ?? null) ? $options['context'] : []);
            if ($context !== []) {
                $draft['context'] = $context;
            }
            if ($config['beforeSend'] !== null) {
                try {
                    $changed = ($config['beforeSend'])($draft);
                } catch (\Throwable $t) {
                    self::debug('beforeSend threw, so the problem was not sent: '.$t->getMessage());

                    return;
                }
                $problem = self::normalise($changed, $kind);
            } else {
                $problem = self::normalise($draft, $kind);
            }
            if ($problem === null) {
                return;
            }
            $id = $problem['kind']."\n".$problem['message']."\n".self::topFrame($problem['stack'] ?? null);
            if (isset(self::$queue[$id])) {
                self::$queue[$id]['count'] = min(self::MAX_COUNT, self::$queue[$id]['count'] + $problem['count']);
                self::$queue[$id]['at'] = $problem['at'];
            } else {
                if (self::$queue === []) {
                    self::$oldest = $now;
                }
                self::$queue[$id] = $problem;
                while (count(self::$queue) > self::MAX_WAITING) {
                    array_shift(self::$queue);
                }
            }
        } finally {
            self::$busy = false;
        }
        // Ten waiting, or a long-running script holding one for a while: send now, briefly.
        if ((count(self::$queue) >= self::MAX_BATCH || microtime(true) - self::$oldest > self::SEND_WHEN_OLDER) && microtime(true) >= self::$notBefore) {
            self::transmit(microtime(true) + self::SEND_TIMEOUT);
        }
    }

    /**
     * The shape the console accepts, whatever beforeSend handed back; null when it is not a problem any more.
     *
     * @return array<string, mixed>|null
     */
    private static function normalise(mixed $p, string $fallbackKind): ?array
    {
        if (! is_array($p) || ! is_string($p['message'] ?? null)) {
            return null;
        }
        $message = self::clip($p['message'], self::MAX_MESSAGE);
        if (trim($message) === '') {
            return null;
        }
        $at = $p['at'] ?? null;
        $out = [
            'kind' => in_array($p['kind'] ?? null, self::KINDS, true) ? $p['kind'] : $fallbackKind,
            'message' => $message,
            'level' => ($p['level'] ?? null) === 'warning' ? 'warning' : 'error',
            'count' => is_int($p['count'] ?? null) ? max(1, min(self::MAX_COUNT, $p['count'])) : 1,
            'at' => is_string($at) && strlen($at) <= 40 && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:?\d{2})$/', $at) === 1 ? $at : self::nowIso(),
        ];
        if (is_string($p['stack'] ?? null) && $p['stack'] !== '') {
            $out['stack'] = self::clip($p['stack'], self::MAX_STACK);
        }
        if (is_string($p['route'] ?? null) && $p['route'] !== '') {
            $out['route'] = self::clip($p['route'], self::MAX_ROUTE);
        }
        if (is_array($p['context'] ?? null)) {
            $context = [];
            foreach ($p['context'] as $name => $value) {
                if (count($context) >= self::MAX_CONTEXT) {
                    break;
                }
                if (is_string($value)) {
                    $context[self::clip((string) $name, self::MAX_CONTEXT_KEY)] = self::clip($value, self::MAX_CONTEXT_VALUE);
                } elseif (is_null($value) || is_bool($value) || is_int($value) || (is_float($value) && is_finite($value))) {
                    $context[self::clip((string) $name, self::MAX_CONTEXT_KEY)] = $value;
                }
            }
            if ($context !== []) {
                $out['context'] = $context;
            }
        }

        return $out;
    }

    // ── Handlers ──────────────────────────────────────────────────────────────────────────────────────────────────────

    private static function onException(\Throwable $e): void
    {
        self::$crashed = true;
        try {
            self::capture('crash', $e, []);
        } catch (\Throwable) {
            // Never a second problem.
        }
        $previous = self::$previousExceptionHandler;
        if ($previous !== null) {
            $previous($e);

            return;
        }
        // No handler before this one: PHP's own behaviour ("PHP Fatal error:  Uncaught ...", exit code 255).
        throw $e;
    }

    private static function onError(int $level, string $message, string $file, int $line): bool
    {
        try {
            if ((error_reporting() & $level) !== 0 && ($level & self::CAPTURED_ERRORS) !== 0 && ! self::$busy) {
                $names = [E_WARNING => 'Warning', E_USER_WARNING => 'Warning', E_USER_ERROR => 'Error', E_RECOVERABLE_ERROR => 'Recoverable error'];
                $trace = '';
                $n = 0;
                foreach (array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 2, self::MAX_FRAMES) as $frame) {
                    $trace .= "\n#".$n++.' '.(isset($frame['file']) ? $frame['file'].'('.($frame['line'] ?? 0).')' : '[internal function]').': '.($frame['class'] ?? '').($frame['type'] ?? '').($frame['function'] ?? '').'()';
                }
                self::capture('log', null, [
                    'message' => ($names[$level] ?? 'Warning').': '.$message,
                    'stack' => ($names[$level] ?? 'Warning').': '.$message.' in '.$file.':'.$line.$trace,
                    'level' => $level === E_WARNING || $level === E_USER_WARNING ? 'warning' : 'error',
                ]);
            }
        } catch (\Throwable) {
            // Never a second problem.
        }
        $previous = self::$previousErrorHandler;
        if ($previous !== null) {
            return (bool) $previous($level, $message, $file, $line);
        }

        // PHP's own handling, as if this handler were not here.
        return false;
    }

    private static function onShutdown(): void
    {
        self::$reserve = null;
        try {
            if (self::$config === null) {
                return;
            }
            $error = error_get_last();
            if (is_array($error) && ($error['type'] & self::FATAL) !== 0) {
                // An uncaught exception reported by onException comes back here as "Uncaught ...": once is enough.
                if (! (self::$crashed && str_starts_with((string) $error['message'], 'Uncaught '))) {
                    $text = strtok((string) $error['message'], "\n");
                    self::capture('crash', null, [
                        'message' => 'Fatal error: '.(is_string($text) ? $text : ''),
                        'stack' => 'Fatal error: '.$error['message'].' in '.$error['file'].':'.$error['line'],
                    ]);
                }
            }
            if (self::$queue !== [] || (self::$config['spool'] !== null && is_file(self::$config['spool']))) {
                self::transmit(microtime(true) + self::SEND_TIMEOUT);
            }
        } catch (\Throwable) {
            // Never a second problem.
        }
    }

    // ── Sending ───────────────────────────────────────────────────────────────────────────────────────────────────────

    /**
     * Sends what waits here and in the spool file until $deadline; keeps in the spool what the console could not take.
     */
    private static function transmit(float $deadline): void
    {
        $config = self::$config;
        if ($config === null || self::$busy) {
            return;
        }
        self::$busy = true;
        try {
            $spool = self::spoolRead();
            $now = microtime(true);
            self::$blockedUntil = max(self::$blockedUntil, (float) ($spool['blockedUntil'] ?? 0));
            self::$notBefore = max(self::$notBefore, (float) ($spool['notBefore'] ?? 0));
            self::$backoff = max(self::$backoff, (float) ($spool['backoff'] ?? 0));
            if ($now < self::$blockedUntil) {
                self::$queue = [];
                self::spoolWrite([], true);

                return;
            }
            if ($now < self::$notBefore) {
                // Not yet: what waits here joins the spool, for a later request (without a spool it stays here).
                if (self::$queue !== [] && $config['spool'] !== null) {
                    self::spoolWrite(self::$queue, false);
                    self::$queue = [];
                }

                return;
            }
            // The spool's problems are older: they go first.
            self::$queue = self::merge(self::spoolTake(), self::$queue);
            $stopped = false;
            while (self::$queue !== [] && microtime(true) < $deadline - 0.05) {
                $taken = array_slice(self::$queue, 0, self::MAX_BATCH, true);
                self::$queue = array_slice(self::$queue, count($taken), null, true);
                [$body, $sent, $rest] = self::fit($taken);
                self::$queue = $rest + self::$queue;
                try {
                    [$status, $retryAfter] = self::post($body, min(self::SEND_TIMEOUT, max(0.1, $deadline - microtime(true))));
                } catch (\Throwable $e) {
                    // A failure inside the sending is no answer: these problems are kept and tried again, never lost.
                    self::debug('could not send: '.$e->getMessage());
                    [$status, $retryAfter] = [0, null];
                }
                if ($status >= 200 && $status < 300) {
                    self::$backoff = 0.0;

                    continue;
                }
                if ($status === 0 || $status === 429 || $status >= 500) {
                    self::$queue = self::merge($sent, self::$queue);
                    $wait = $retryAfter;
                    if ($wait === null) {
                        self::$backoff = self::$backoff > 0 ? min(self::BACKOFF_MAX, self::$backoff * 2) : self::BACKOFF_FIRST;
                        $wait = self::$backoff;
                    }
                    self::$notBefore = microtime(true) + $wait;
                    self::debug('the console answered '.($status ?: 'nothing').'; trying again in '.(int) round($wait).' s');
                    $stopped = true;
                    break;
                }
                if ($status === 401 || $status === 403) {
                    self::$blockedUntil = microtime(true) + self::BLOCKED;
                    self::$queue = [];
                    self::debugOnce($status, 'the console answered '.$status.' ('.($status === 401 ? 'the key is not known' : 'the site is not verified or its monitoring is off').'): nothing is sent for an hour');
                    self::spoolWrite([], true);

                    return;
                }
                self::debugOnce($status, 'the console answered '.$status.': those problems were dropped');
            }
            // What is left (the console asked to wait, or the time ran out) goes to the spool for a later request.
            if (self::$queue !== [] && $config['spool'] !== null) {
                self::spoolWrite(self::$queue, false);
                self::$queue = [];
            } elseif (! $stopped && $spool !== null) {
                self::spoolWrite([], false);
            }
        } catch (\Throwable $e) {
            self::debug('could not send: '.$e->getMessage());
        } finally {
            self::$busy = false;
            self::$oldest = microtime(true);
        }
    }

    /**
     * @param  array<string, array<string, mixed>>  $front
     * @param  array<string, array<string, mixed>>  $back
     * @return array<string, array<string, mixed>>
     */
    private static function merge(array $front, array $back): array
    {
        foreach ($back as $id => $p) {
            if (isset($front[$id])) {
                $front[$id]['count'] = min(self::MAX_COUNT, $front[$id]['count'] + $p['count']);
                $front[$id]['at'] = $p['at'];
            } else {
                $front[$id] = $p;
            }
        }
        while (count($front) > self::MAX_WAITING) {
            array_shift($front);
        }

        return $front;
    }

    /** @param  list<array<string, mixed>>  $problems */
    private static function encode(array $problems): string
    {
        $config = self::$config ?? [];
        $body = ['sdk' => ['name' => self::SDK_NAME, 'version' => self::VERSION], 'platform' => $config['platform'] ?? 'server', 'runtime' => $config['runtime'] ?? 'php'];
        if (($config['release'] ?? null) !== null) {
            $body['release'] = $config['release'];
        }
        if (($config['environment'] ?? null) !== null) {
            $body['environment'] = $config['environment'];
        }
        $body['errors'] = array_map(static function (array $p): array {
            if (isset($p['context'])) {
                $p['context'] = (object) $p['context'];
            }

            return $p;
        }, $problems);

        return (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION);
    }

    /**
     * The JSON for a batch, cut to fit under 64 KB: long stacks are halved first, then fewer problems go in one request.
     *
     * @param  array<string, array<string, mixed>>  $entries
     * @return array{0: string, 1: array<string, array<string, mixed>>, 2: array<string, array<string, mixed>>}
     */
    private static function fit(array $entries): array
    {
        $rest = [];
        $body = '';
        for ($round = 0; $round < 200; $round++) {
            $body = self::encode(array_values($entries));
            if (strlen($body) <= self::BODY_LIMIT) {
                break;
            }
            $longest = null;
            foreach ($entries as $id => $p) {
                if (isset($p['stack']) && strlen($p['stack']) > 1000 && ($longest === null || strlen($p['stack']) > strlen($entries[$longest]['stack']))) {
                    $longest = $id;
                }
            }
            if ($longest !== null) {
                $stack = $entries[$longest]['stack'];
                $entries[$longest]['stack'] = self::clip($stack, intdiv(self::length($stack), 2))."\n[cut]";

                continue;
            }
            if (count($entries) > 1) {
                $last = array_key_last($entries);
                $rest = [$last => $entries[$last]] + $rest;
                unset($entries[$last]);

                continue;
            }
            $id = (string) array_key_first($entries);
            if (self::length($entries[$id]['message']) > 1000) {
                $entries[$id]['message'] = self::clip($entries[$id]['message'], intdiv(self::length($entries[$id]['message']), 2));
            } elseif (isset($entries[$id]['context'])) {
                unset($entries[$id]['context']);
            } elseif (isset($entries[$id]['stack'])) {
                unset($entries[$id]['stack']);
            } else {
                break;
            }
        }

        return [$body, $entries, $rest];
    }

    /** @return array{0: int, 1: float|null} the answer's status (0: no answer) and its Retry-After in seconds */
    private static function post(string $body, float $timeout): array
    {
        $config = self::$config;
        $headers = ['Authorization: Bearer '.$config['key'], 'Content-Type: application/json', 'User-Agent: '.self::SDK_NAME.'/'.self::VERSION];
        $retryAfter = null;
        if ($config['transport'] === 'curl') {
            $curl = curl_init($config['endpoint']);
            if ($curl === false) {
                return [0, null];
            }
            curl_setopt_array($curl, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => array_merge($headers, ['Expect:']),
                CURLOPT_TIMEOUT_MS => (int) max(100, $timeout * 1000),
                CURLOPT_CONNECTTIMEOUT_MS => (int) max(100, min(1000, $timeout * 1000)),
                CURLOPT_NOSIGNAL => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$retryAfter): int {
                    if (stripos($line, 'retry-after:') === 0) {
                        $retryAfter = trim(substr($line, 12));
                    }

                    return strlen($line);
                },
            ]);
            $ok = curl_exec($curl);
            $status = $ok === false ? 0 : (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            if ($ok === false) {
                self::debug('could not reach '.$config['endpoint'].': '.curl_error($curl));
            }
        } else {
            $context = stream_context_create(['http' => [
                'method' => 'POST',
                'header' => implode("\r\n", array_merge($headers, ['Connection: close'])),
                'content' => $body,
                'timeout' => max(0.1, $timeout),
                'ignore_errors' => true,
                'follow_location' => 0,
            ]]);
            // ⚠️ The answer's headers come from the stream itself (wrapper_data), the same in every PHP version. Not
            // $http_response_header through get_defined_vars(): PHP 8.1-8.3 fill it only in a function that names it,
            // so every answer read as none (and was sent again); PHP 8.5 deprecates naming it. Not
            // http_get_last_response_headers() either: PHP 8.4 and later only.
            $status = 0;
            $stream = @fopen($config['endpoint'], 'r', false, $context);
            if ($stream === false) {
                self::debug('could not reach '.$config['endpoint']);
            } else {
                $meta = stream_get_meta_data($stream);
                @stream_get_contents($stream, 65536);
                fclose($stream);
                foreach (is_array($meta['wrapper_data'] ?? null) ? $meta['wrapper_data'] : [] as $line) {
                    if (! is_string($line)) {
                        continue;
                    }
                    if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                        $status = (int) $m[1];
                    } elseif (stripos($line, 'retry-after:') === 0) {
                        $retryAfter = trim(substr($line, 12));
                    }
                }
            }
        }

        return [$status, self::retryAfter($retryAfter)];
    }

    private static function retryAfter(?string $value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }
        // Not ctype_digit(): the ctype extension is not in every PHP (without it, a 429 threw here and its problems
        // were lost).
        if (preg_match('/^\d+$/', $value) === 1) {
            return min(self::RETRY_AFTER_MAX, (float) $value);
        }
        $when = strtotime($value);

        return $when === false ? null : min(self::RETRY_AFTER_MAX, max(0.0, $when - microtime(true)));
    }

    // ── The spool: what could not be sent, kept for a later request ───────────────────────────────────────────────────

    /** @return array<string, mixed>|null */
    private static function spoolRead(): ?array
    {
        $path = self::$config['spool'] ?? null;
        if ($path === null || ! is_file($path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($path), true);

        return is_array($data) ? $data : null;
    }

    /** @return array<string, array<string, mixed>> the spool's problems, now this request's to send */
    private static function spoolTake(): array
    {
        $taken = [];
        self::spoolChange(static function (array $data) use (&$taken): array {
            foreach (is_array($data['problems'] ?? null) ? $data['problems'] : [] as $p) {
                $p = self::normalise($p, 'exception');
                if ($p !== null) {
                    $taken[$p['kind']."\n".$p['message']."\n".self::topFrame($p['stack'] ?? null)] = $p;
                }
            }
            $data['problems'] = [];

            return $data;
        });

        return $taken;
    }

    /** @param  array<string, array<string, mixed>>  $problems */
    private static function spoolWrite(array $problems, bool $blocked): void
    {
        self::spoolChange(static function (array $data) use ($problems, $blocked): array {
            $have = [];
            foreach (is_array($data['problems'] ?? null) ? $data['problems'] : [] as $p) {
                $p = self::normalise($p, 'exception');
                if ($p !== null) {
                    $have[$p['kind']."\n".$p['message']."\n".self::topFrame($p['stack'] ?? null)] = $p;
                }
            }
            $data['problems'] = $blocked ? [] : array_values(self::merge($have, $problems));
            $data['notBefore'] = self::$notBefore;
            $data['backoff'] = self::$backoff;
            $data['blockedUntil'] = self::$blockedUntil;

            return $data;
        });
    }

    private static function spoolChange(callable $change): void
    {
        $path = self::$config['spool'] ?? null;
        if ($path === null) {
            return;
        }
        $old = umask(0077);
        $handle = @fopen($path, 'c+');
        umask($old);
        if ($handle === false) {
            return;
        }
        try {
            if (! flock($handle, LOCK_EX)) {
                return;
            }
            $data = json_decode((string) stream_get_contents($handle), true);
            $data = $change(is_array($data) ? $data : ['v' => 1]);
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
            fflush($handle);
            flock($handle, LOCK_UN);
            $empty = ($data['problems'] ?? []) === [] && (float) ($data['notBefore'] ?? 0) <= microtime(true) && (float) ($data['blockedUntil'] ?? 0) <= microtime(true);
        } finally {
            fclose($handle);
        }
        // Nothing kept and nothing to wait for: no file, so the next request has nothing to look at.
        if ($empty ?? false) {
            @unlink($path);
        }
    }
}
