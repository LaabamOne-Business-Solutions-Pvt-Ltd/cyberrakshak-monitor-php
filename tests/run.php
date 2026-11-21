<?php

// Tests for cyberrakshak/monitor (src/CyberRakshakMonitor.php), against tests/fake-server.mjs only (127.0.0.1: never a
// real Cyber Rakshak host). The class is loaded by Composer's autoloader, as an app gets it:
//   composer install && composer test        (or: php tests/run.php; php -n tests/run.php for no curl, no mbstring)
// Uses the fake server named by CR_TEST_SERVER, or starts its own with node (Node.js 18 or later on the PATH).

declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';
if (! class_exists(\CyberRakshak\Monitor::class)) {
    fwrite(STDERR, "vendor/autoload.php does not load CyberRakshak\\Monitor: run composer install (or composer dump-autoload)\n");
    exit(1);
}

use CyberRakshak\Monitor;

const KEY = 'crk_00000000000000000000000000000000';
// What each child process requires: the autoloader too.
$GLOBALS['sdk'] = realpath(__DIR__.'/../vendor/autoload.php');
$GLOBALS['server'] = null;
$base = getenv('CR_TEST_SERVER');
if (! $base) {
    $GLOBALS['server'] = proc_open(['node', __DIR__.'/fake-server.mjs'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => STDERR], $pipes);
    $GLOBALS['serverPipes'] = $pipes;
    $base = json_decode((string) fgets($pipes[1]), true)['url'];
}
$GLOBALS['base'] = $base;

function endpoint(): string
{
    return $GLOBALS['base'].'/api/v1/app-reports';
}

function control(string $path, ?array $body = null): mixed
{
    $options = ['http' => ['method' => $body === null ? 'GET' : 'POST', 'timeout' => 30, 'ignore_errors' => true, 'header' => 'Content-Type: application/json', 'content' => $body === null ? '' : json_encode($body)]];

    return json_decode((string) file_get_contents($GLOBALS['base'].'/__control/'.$path, false, stream_context_create($options)), true);
}

function requests(int $count = 0, int $timeout = 5000): array
{
    return $count ? control("wait?count=$count&timeout=$timeout") : control('requests');
}

function problems(array $requests): array
{
    return array_merge([], ...array_map(fn ($r) => $r['body']['errors'], $requests));
}

function spoolDir(): string
{
    $dir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'cr-php-sdk-'.bin2hex(random_bytes(6));
    mkdir($dir);

    return $dir;
}

function start(array $extra = []): void
{
    Monitor::init($extra + ['key' => KEY, 'endpoint' => endpoint(), 'handleExceptions' => false, 'spool' => false]);
}

/**
 * Runs PHP code in a new process (the library loaded, KEY and ENDPOINT defined), with $phpArgs before the file:
 * [exit code, stdout, stderr, seconds].
 */
function runPhp(string $code, array $phpArgs = []): array
{
    $file = tempnam(sys_get_temp_dir(), 'crphp').'.php';
    file_put_contents($file, "<?php\nrequire ".var_export($GLOBALS['sdk'], true).";\nconst KEY = '".KEY."';\nconst ENDPOINT = ".var_export(endpoint(), true).";\n".$code);
    $t = microtime(true);
    $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-d', 'log_errors=0', '-d', 'error_reporting=-1', ...$phpArgs, $file], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    $code = proc_close($p);
    @unlink($file);

    return [$code, $out, $err, microtime(true) - $t];
}

$tests = [];
function test(string $name, callable $fn): void
{
    $GLOBALS['tests'][] = [$name, $fn];
}

final class Failed extends Exception {}

function check(bool $ok, string $what): void
{
    if (! $ok) {
        throw new Failed($what);
    }
}

function same(mixed $want, mixed $got, string $what = ''): void
{
    if ($want !== $got) {
        throw new Failed(($what ? $what.': ' : '').'expected '.json_encode($want, JSON_UNESCAPED_UNICODE).', got '.json_encode($got, JSON_UNESCAPED_UNICODE));
    }
}

function clean(array $requests): void
{
    foreach ($requests as $r) {
        same([], $r['violations'], 'request '.$r['n'].' broke the contract');
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

test('scrub: every shared vector', function () {
    $vectors = json_decode((string) file_get_contents(__DIR__.'/scrub-vectors.json'), true)['vectors'];
    foreach ($vectors as $v) {
        same($v['out'], Monitor::scrub($v['in']), json_encode($v['in'], JSON_UNESCAPED_UNICODE));
    }
    foreach ([str_repeat('AbCdEfGh0123456789xyzXYZ+/', 1231), str_repeat('a', 32000), str_repeat('token', 6400), str_repeat('eyJ', 10000)] as $worst) {
        $t = microtime(true);
        Monitor::scrub($worst);
        check(microtime(true) - $t < 3, 'scrubbing took '.round(microtime(true) - $t, 2).' s');
    }
});

foreach (['curl', 'stream'] as $transport) {
    test("a captured exception in the contract's shape, scrubbed ($transport)", function () use ($transport) {
        start(['release' => '2026.11.21+3', 'environment' => 'Production', 'context' => ['region' => 'blr1'], 'transport' => $transport]);
        Monitor::captureException(new RuntimeException('boom for asha@example.com'), ['route' => '/orders/42?token=abc', 'context' => ['email' => 'x@example.org', 'n' => 3, 'ok' => true, 'obj' => ['no' => 1]]]);
        same(true, Monitor::flush(3));
        $r = requests();
        same(1, count($r));
        clean($r);
        same('Bearer '.KEY, $r[0]['authorization']);
        $b = $r[0]['body'];
        same(['name' => 'cyberrakshak-php', 'version' => '1.1.0'], $b['sdk']);
        same('server', $b['platform']);
        check(preg_match('/^php \d+\.\d+$/', $b['runtime']) === 1, 'runtime '.$b['runtime']);
        same('2026.11.21+3', $b['release']);
        same('production', $b['environment']);
        $p = $b['errors'][0];
        same(['exception', 'RuntimeException: boom for [email]', '/orders/42', 'error', 1], [$p['kind'], $p['message'], $p['route'], $p['level'], $p['count']]);
        check(str_contains($p['stack'], 'run.php'), 'stack names the file');
        same(['region' => 'blr1', 'email' => '[email]', 'n' => 3, 'ok' => true], $p['context']);
    });
}

test('the trace never carries arguments', function () {
    start();
    $f = function (string $password) {
        return new RuntimeException('inside');
    };
    Monitor::captureException($f('hunter2-secret-argument'));
    Monitor::flush(3);
    check(! str_contains(json_encode(requests()), 'hunter2-secret-argument'), 'an argument was sent');
});

test('repeats are counted, not resent', function () {
    start();
    for ($i = 0; $i < 5; $i++) {
        Monitor::captureException(new LogicException('same problem'));
    }
    Monitor::captureMessage('a message', ['level' => 'error']);
    Monitor::flush(3);
    $r = requests();
    clean($r);
    same(1, count($r));
    same(['LogicException: same problem', 5], [$r[0]['body']['errors'][0]['message'], $r[0]['body']['errors'][0]['count']]);
    same(['log', 'error', 'a message'], [$r[0]['body']['errors'][1]['kind'], $r[0]['body']['errors'][1]['level'], $r[0]['body']['errors'][1]['message']]);
});

test('at most 10 in one request: sent as soon as 10 wait', function () {
    start();
    for ($i = 0; $i < 25; $i++) {
        Monitor::captureMessage("distinct $i");
    }
    same(2, count(requests()), 'sent at 10 and 20 already');
    Monitor::flush(3);
    $r = requests();
    clean($r);
    same([10, 10, 5], array_map(fn ($x) => count($x['body']['errors']), $r));
});

test('at most 50 wait while the console is down; the oldest go first', function () {
    control('plan', ['responses' => [['status' => 500]]]);
    start();
    for ($i = 0; $i < 60; $i++) {
        Monitor::captureMessage("waiting $i");
    }
    same(1, count(requests()), 'one try, then the backoff');
    usleep(2_100_000);
    Monitor::flush(5);
    $later = array_slice(requests(), 1);
    clean($later);
    $all = problems($later);
    same(50, count($all));
    same('waiting 10', $all[0]['message']);
});

test('429: kept, not sent before Retry-After, sent after it', function () {
    control('plan', ['responses' => [['status' => 429, 'retryAfter' => '1']]]);
    start();
    Monitor::captureMessage('slow down');
    same(false, Monitor::flush(3));
    Monitor::flush(1);
    same(1, count(requests()), 'nothing before Retry-After');
    usleep(1_100_000);
    same(true, Monitor::flush(3));
    $r = requests();
    same(2, count($r));
    check($r[1]['at'] - $r[0]['at'] >= 1000, 'waited '.($r[1]['at'] - $r[0]['at']).' ms');
    same('slow down', $r[1]['body']['errors'][0]['message']);
});

test('429 at the end of a request: kept in the spool, sent by a later request', function () {
    $dir = spoolDir();
    control('plan', ['responses' => [['status' => 429, 'retryAfter' => '1']]]);
    [$code] = runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => ".var_export($dir, true)."]);\n\\CyberRakshak\\Monitor::captureMessage('kept for later');\n");
    same(0, $code);
    same(1, count(requests()));
    check(count(glob($dir.'/cyberrakshak-monitor-*.json')) === 1, 'a spool file was written');
    usleep(1_200_000);
    runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => ".var_export($dir, true)."]);\n");
    $r = requests(2, 3000);
    clean($r);
    same(2, count($r));
    same('kept for later', $r[1]['body']['errors'][0]['message']);
    same([], glob($dir.'/cyberrakshak-monitor-*.json'), 'the spool is gone once sent');
});

// ⚠️ ctype is an extension some PHP builds leave out (Alpine's php-ctype, Ubuntu's PHP run with php -n): the
// library once read Retry-After with ctype_digit(), so a 429 threw inside it and its problems were lost.
test('without the ctype extension, a 429 with Retry-After still keeps its problems (in the spool)', function () {
    $dir = spoolDir();
    control('plan', ['responses' => [['status' => 429, 'retryAfter' => '1']]]);
    [$code, $out, $err] = runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => ".var_export($dir, true)."]);\n\\CyberRakshak\\Monitor::captureMessage('kept without ctype');\necho function_exists('ctype_digit') ? 'ctype' : 'no ctype';\n", ['-d', 'disable_functions=ctype_digit']);
    same(0, $code, 'exit code (output: '.trim($out.$err).')');
    same('no ctype', trim($out));
    same(1, count(requests()));
    $files = glob($dir.'/cyberrakshak-monitor-*.json');
    check(count($files) === 1 && str_contains((string) file_get_contents($files[0]), 'kept without ctype'), 'the 429 kept it in the spool');
});

test('422: dropped, never retried', function () {
    control('plan', ['responses' => [['status' => 422]]]);
    start();
    Monitor::captureMessage('first');
    Monitor::flush(3);
    Monitor::captureMessage('second');
    Monitor::flush(3);
    same([['first'], ['second']], array_map(fn ($r) => array_column($r['body']['errors'], 'message'), requests()));
});

test('401: dropped, and nothing more for an hour (this process and the next)', function () {
    $dir = spoolDir();
    control('plan', ['responses' => [['status' => 401]]]);
    start(['spool' => $dir]);
    Monitor::captureMessage('first');
    Monitor::flush(3);
    Monitor::captureMessage('second');
    Monitor::flush(1);
    runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => ".var_export($dir, true)."]);\n\\CyberRakshak\\Monitor::captureMessage('third');\n");
    same(1, count(requests()));
});

test('beforeSend: null drops, a changed problem is sent as changed, one that throws drops', function () {
    start(['beforeSend' => fn ($p) => null]);
    Monitor::captureMessage('dropped');
    Monitor::flush(1);
    start(['context' => ['tenant' => 't1'], 'beforeSend' => function ($p) {
        $p['message'] = 'changed';
        unset($p['context']);

        return $p;
    }]);
    Monitor::captureMessage('original');
    Monitor::flush(3);
    start(['beforeSend' => function ($p) {
        throw new RuntimeException('bad filter');
    }]);
    Monitor::captureMessage('also dropped');
    Monitor::flush(1);
    $r = requests();
    clean($r);
    same(1, count($r));
    same('changed', $r[0]['body']['errors'][0]['message']);
    check(! isset($r[0]['body']['errors'][0]['context']), 'context removed');
});

test('sampleRate 0, enabled false and a wrong key send nothing', function () {
    start(['sampleRate' => 0]);
    for ($i = 0; $i < 12; $i++) {
        Monitor::captureMessage("sampled $i");
    }
    Monitor::flush(1);
    start(['enabled' => false]);
    Monitor::captureMessage('off');
    Monitor::flush(1);
    start(['key' => 'crw_00000000000000000000000000000000']);
    Monitor::captureMessage('bad key');
    Monitor::flush(1);
    same([], requests());
});

test('big problems still go in bodies under 64 KB', function () {
    start();
    $deep = function (int $n) use (&$deep) {
        return $n === 0 ? new RuntimeException('deep') : $deep($n - 1);
    };
    for ($i = 0; $i < 10; $i++) {
        Monitor::captureMessage("huge $i ".str_repeat('é', 3990));
    }
    Monitor::captureException($deep(3000));
    Monitor::flush(5);
    $r = requests();
    clean($r);
    same(11, count(problems($r)));
    foreach ($r as $x) {
        check($x['bytes'] <= 65536, $x['bytes'].' bytes');
    }
});

test('nothing it is given makes it throw', function () {
    $odd = [null, 0, '', "\xff\xfe broken utf-8", [1, 2], new stdClass, 1.5, INF, NAN, true];
    foreach ($odd as $x) {
        Monitor::captureMessage($x);
    }
    start();
    foreach ($odd as $x) {
        Monitor::captureMessage($x, ['route' => $x, 'context' => ['x' => $x, 'y' => [1], 'z' => "\xc3"], 'level' => $x]);
        Monitor::captureException(new Exception("\xff bad bytes"), ['route' => $x, 'context' => ['x' => $x]]);
    }
    Monitor::flush(3);
    clean(requests());
});

test('close() gives back the handlers that were there before', function () {
    $mine = fn ($e) => null;
    set_exception_handler($mine);
    Monitor::init(['key' => KEY, 'endpoint' => endpoint(), 'spool' => false, 'captureErrors' => true]);
    Monitor::close();
    same($mine, set_exception_handler(null));
    restore_exception_handler();
    restore_exception_handler();
});

test("an uncaught exception: reported once, then PHP's own 'Uncaught' and exit code 255", function () {
    [$code, $out, $err] = runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false]);\nthrow new RuntimeException('crash-boom');\n");
    same(255, $code);
    check(str_contains($out.$err, 'Uncaught RuntimeException: crash-boom'), 'PHP printed it: '.$out.$err);
    $r = requests(1, 3000);
    clean($r);
    same([['crash', 'RuntimeException: crash-boom']], array_map(fn ($p) => [$p['kind'], $p['message']], problems($r)));
});

test('the exception handler set before init() still runs', function () {
    [$code, $out] = runPhp("set_exception_handler(function (Throwable \$e) { echo 'host handler ran: '.\$e->getMessage(); });\n\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false]);\nthrow new RuntimeException('handled-boom');\n");
    check(str_contains($out, 'host handler ran: handled-boom'), 'host handler output: '.$out);
    same([['crash', 'RuntimeException: handled-boom']], array_map(fn ($p) => [$p['kind'], $p['message']], problems(requests(1, 3000))));
});

test('a fatal error (out of memory) is reported at shutdown, and the exit code is PHP\'s own', function () {
    $limit = "ini_set('memory_limit', '16M');\n";
    $loop = "\$a = [];\nwhile (true) { \$a[] = str_repeat('x', 100000); }\n";
    // ⚠️ What PHP itself does here differs by build, so the same script without the library says it: its exit code
    // (255; 1 on Ubuntu's PHP 8.1.34), and whether any shutdown function runs after running out of memory (Ubuntu's PHP
    // 8.1.34 runs none, so nothing at all can report it there; the official 8.1.31 does). The library changes neither.
    [$plain, $plainOut, $plainErr] = runPhp($limit."register_shutdown_function(function () { echo 'shutdown ran'; });\n".$loop);
    check($plain !== 0 && str_contains($plainOut.$plainErr, 'Allowed memory size'), 'without the library: exit code '.$plain);
    $shutdownRuns = str_contains($plainOut, 'shutdown ran');
    control('reset', []);
    [$code, $out, $err] = runPhp($limit."\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false]);\n".$loop);
    same($plain, $code, 'exit code, PHP\'s own without the library (output: '.trim($out.$err).')');
    check(str_contains($out.$err, 'Allowed memory size'), 'PHP printed it');
    if (! $shutdownRuns) {
        same([], requests(), 'nothing can have been sent: this PHP ran no shutdown function');
        echo '        (PHP '.PHP_VERSION." runs no shutdown function after running out of memory: nothing can report it)\n";

        return;
    }
    $p = problems(requests(1, 3000));
    same(1, count($p));
    same('crash', $p[0]['kind']);
    check(str_starts_with($p[0]['message'], 'Fatal error: Allowed memory size'), $p[0]['message']);
});

test("captureErrors: warnings reported, PHP's own handling unchanged, @ respected, the handler before still runs", function () {
    [$code, $out, $err] = runPhp(
        "\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false, 'captureErrors' => true]);\n".
        "\$a = [];\necho \$a['missing'] ?? '';\necho \$a['missing'];\n@\$a['quiet'];\ntrigger_error('custom warning', E_USER_WARNING);\necho 'carried on';\n"
    );
    same(0, $code);
    check(str_contains($err.$out, 'Undefined array key "missing"'), 'PHP printed its warning');
    check(str_contains($out, 'carried on'), 'the script went on');
    $p = problems(requests(1, 3000));
    same([['log', 'warning', 'Warning: Undefined array key "missing"'], ['log', 'warning', 'Warning: custom warning']], array_map(fn ($x) => [$x['kind'], $x['level'], $x['message']], $p));
    control('reset', []);
    [$code, $out] = runPhp(
        "set_error_handler(function (\$n, \$s) { echo 'host error handler: '.\$s; return true; });\n".
        "\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false, 'captureErrors' => true]);\n".
        "trigger_error('second', E_USER_WARNING);\n"
    );
    check(str_contains($out, 'host error handler: second'), 'host handler ran: '.$out);
    same(1, count(problems(requests(1, 3000))));
});

test('a slow console holds the end of a script for about 2 s at most', function () {
    control('plan', ['responses' => [['status' => 204, 'delayMs' => 8000]]]);
    [$code, $out, , $took] = runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false]);\n\\CyberRakshak\\Monitor::captureMessage('slow');\necho 'done';\n");
    same(0, $code);
    check(str_contains($out, 'done'), 'ran');
    check($took < 4.5, 'took '.round($took, 1).' s');
});

test('the command is the route of a script; the key is never printed', function () {
    control('plan', ['responses' => [['status' => 401]]]);
    [, $out, $err] = runPhp("\\CyberRakshak\\Monitor::init(['key' => KEY, 'endpoint' => ENDPOINT, 'spool' => false, 'debug' => true, 'platform' => 'script']);\n\\CyberRakshak\\Monitor::captureMessage('x');\n");
    check(str_contains($err, '401'), 'debug said 401: '.$err);
    check(! str_contains($out.$err, 'crk_0'), 'the key was printed');
    $r = requests();
    same('script', $r[0]['body']['platform']);
    check(preg_match('/^cr\w*(\.tmp)?\.php$/', $r[0]['body']['errors'][0]['route']) === 1, 'route '.$r[0]['body']['errors'][0]['route']);
});

test('scrubNames and scrubPatterns add to the built-in rules; a secret context name goes as [removed]', function () {
    start(['scrubNames' => ['x-brand-key', 'face.key', 'bad name', 7], 'scrubPatterns' => ['/faces\/[A-Za-z0-9\/_.-]+/', '/upload-[0-9]+/', '/(/', '/x*/', 7], 'context' => ['client_secret' => 'abc', 'region' => 'dub1']]);
    Monitor::captureException(new RuntimeException('x-brand-key=B1 for faces/2026/a.jpg (upload-77)'), ['route' => '/files/face.key=K9', 'context' => ['user_pin' => 1234, 'iban' => 'IE29AIBK93115212345678', 'x-tink-signature' => true, 'spinning' => 'yes', 'japan' => 3]]);
    same(true, Monitor::flush(3));
    $r = requests(1);
    clean($r);
    $p = problems($r)[0];
    same('RuntimeException: x-brand-key=[removed] for [removed] ([removed])', $p['message']);
    same('/files/face.key=[removed]', $p['route']);
    same(['client_secret' => '[removed]', 'region' => 'dub1', 'user_pin' => '[removed]', 'iban' => '[removed]', 'x-tink-signature' => '[removed]', 'spinning' => 'yes', 'japan' => 3], $p['context']);
    same('pin=[removed] x-brand-key=[removed] password=[removed]', Monitor::scrub('pin=1 x-brand-key=2 password=3'));
    Monitor::close();
    same('x-brand-key=2', Monitor::scrub('x-brand-key=2'));
});

test('scrubNames and scrubPatterns: at most 50 names and 20 patterns; the built-in rules cannot be removed', function () {
    $names = ['ok_name'];
    for ($i = 0; $i < 60; $i++) {
        $names[] = 'n'.$i;
    }
    $patterns = ['/fine/'];
    for ($i = 0; $i < 25; $i++) {
        $patterns[] = '/p'.$i.'q/';
    }
    start(['scrubNames' => $names, 'scrubPatterns' => $patterns]);
    same('ok_name=[removed] n48=[removed] n49=3 [removed] [removed] p19q', Monitor::scrub('ok_name=1 n48=2 n49=3 fine p18q p19q'));
    same('password=[removed] card [card]', Monitor::scrub('password=1 card 4111 1111 1111 1111'));
});

// ── Runner ────────────────────────────────────────────────────────────────────────────────────────────────────────────

$pass = 0;
$fail = 0;
foreach ($tests as [$name, $fn]) {
    Monitor::close();
    control('reset', []);
    $t = microtime(true);
    try {
        $fn();
        $pass++;
        echo '  ok    '.$name.' ('.round((microtime(true) - $t) * 1000)." ms)\n";
    } catch (Throwable $e) {
        $fail++;
        echo '  FAIL  '.$name."\n        ".get_class($e).': '.$e->getMessage().' at line '.$e->getLine()."\n";
    }
}
Monitor::close();
echo 'php '.PHP_VERSION.' ('.(function_exists('curl_init') ? 'curl' : 'no curl')."): $pass passed, $fail failed\n";
if ($GLOBALS['server'] !== null) {
    fclose($GLOBALS['serverPipes'][0]);
    proc_close($GLOBALS['server']);
}
exit($fail ? 1 : 0);
