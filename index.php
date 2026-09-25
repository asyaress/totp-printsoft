<?php
declare(strict_types=1);

/*
 * Native PHP TOTP portal.
 *
 * Default first-run credentials (localhost only):
 *   Username: admin
 *   Password: Admin@123
 *
 * Vercel production uses DATABASE_URL plus TOTP_ENCRYPTION_KEY. Local
 * development can keep using the protected file fallback.
 */

const STORAGE_HEADER = "<?php exit; ?>\n";
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;

function env_value(string $key, string $fallback): string
{
    $value = getenv($key);
    return is_string($value) && $value !== '' ? $value : $fallback;
}

function database_url(): ?string
{
    foreach (['DATABASE_URL', 'POSTGRES_URL'] as $name) {
        $value = getenv($name);
        if (is_string($value) && trim($value) !== '') {
            return trim($value);
        }
    }
    return null;
}

function database_enabled(): bool
{
    return database_url() !== null;
}

function is_vercel_runtime(): bool
{
    $value = getenv('VERCEL');
    return is_string($value) && ($value === '1' || strtolower($value) === 'true');
}

/** Returns a 32-byte binary key, not the encoded environment value. */
function encryption_key(bool $required = false): ?string
{
    static $resolved = false;
    static $key = null;

    if (!$resolved) {
        $resolved = true;
        $raw = getenv('TOTP_ENCRYPTION_KEY');
        if (is_string($raw) && trim($raw) !== '') {
            $raw = trim($raw);
            if (preg_match('/^[a-f0-9]{64}$/i', $raw) === 1) {
                $decoded = hex2bin($raw);
            } else {
                $decoded = base64_decode($raw, true);
            }
            if (!is_string($decoded) || strlen($decoded) !== 32) {
                throw new RuntimeException('TOTP_ENCRYPTION_KEY harus berupa Base64 32 byte atau 64 karakter hex.');
            }
            $key = $decoded;
        }
    }

    if ($required && !is_string($key)) {
        throw new RuntimeException('TOTP_ENCRYPTION_KEY wajib dikonfigurasi untuk penyimpanan database.');
    }
    return $key;
}

function protect_value(string $plaintext, string $purpose): string
{
    $key = encryption_key(true);
    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $purpose, 16);
    if (!is_string($ciphertext) || strlen($tag) !== 16) {
        throw new RuntimeException('Data sensitif tidak dapat dienkripsi.');
    }
    return 'enc:v1:' . base64_encode($iv . $tag . $ciphertext);
}

function reveal_value(string $protected, string $purpose): string
{
    if (strpos($protected, 'enc:v1:') !== 0) {
        return $protected;
    }
    $payload = base64_decode(substr($protected, 7), true);
    if (!is_string($payload) || strlen($payload) < 29) {
        throw new RuntimeException('Format data terenkripsi tidak valid.');
    }
    $iv = substr($payload, 0, 12);
    $tag = substr($payload, 12, 16);
    $ciphertext = substr($payload, 28);
    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', encryption_key(true), OPENSSL_RAW_DATA, $iv, $tag, $purpose);
    if (!is_string($plaintext)) {
        throw new RuntimeException('Data terenkripsi tidak dapat dibuka. Periksa TOTP_ENCRYPTION_KEY.');
    }
    return $plaintext;
}

function database_connection(): PDO
{
    static $connection = null;
    if ($connection instanceof PDO) {
        return $connection;
    }

    $url = database_url();
    if ($url === null) {
        throw new RuntimeException('DATABASE_URL belum dikonfigurasi.');
    }

    if (strpos($url, 'sqlite:') === 0) {
        if (is_vercel_runtime()) {
            throw new RuntimeException('SQLite tidak persisten di Vercel. Gunakan PostgreSQL pada DATABASE_URL.');
        }
        $connection = new PDO($url);
    } else {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'], $parts['path']) || !in_array($parts['scheme'], ['postgres', 'postgresql'], true)) {
            throw new RuntimeException('DATABASE_URL harus berupa URL PostgreSQL yang valid.');
        }
        $query = [];
        if (isset($parts['query'])) {
            parse_str((string) $parts['query'], $query);
        }
        $host = (string) $parts['host'];
        $port = isset($parts['port']) ? (int) $parts['port'] : 5432;
        $database = rawurldecode(ltrim((string) $parts['path'], '/'));
        $sslmode = isset($query['sslmode']) ? (string) $query['sslmode'] : 'require';
        $dsn = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $database . ';sslmode=' . $sslmode;
        $connection = new PDO(
            $dsn,
            isset($parts['user']) ? rawurldecode((string) $parts['user']) : '',
            isset($parts['pass']) ? rawurldecode((string) $parts['pass']) : ''
        );
    }

    $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $connection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $connection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    return $connection;
}

function ensure_database_schema(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }

    $pdo->exec('CREATE TABLE IF NOT EXISTS totp_app_state (
        id SMALLINT PRIMARY KEY,
        payload TEXT NOT NULL,
        revision BIGINT NOT NULL DEFAULT 1,
        updated_at BIGINT NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS totp_sessions (
        session_id VARCHAR(128) PRIMARY KEY,
        payload TEXT NOT NULL,
        expires_at BIGINT NOT NULL
    )');
    $pdo->exec('CREATE INDEX IF NOT EXISTS totp_sessions_expiry_idx ON totp_sessions (expires_at)');
    $ready = true;
}

final class DatabaseSessionHandler implements SessionHandlerInterface
{
    private PDO $pdo;
    private int $lifetime;

    public function __construct(PDO $pdo, int $lifetime)
    {
        $this->pdo = $pdo;
        $this->lifetime = $lifetime;
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    private function storageId(string $id): string
    {
        return hash_hmac('sha256', $id, encryption_key(true));
    }

    public function read(string $id): string|false
    {
        $storageId = $this->storageId($id);
        $statement = $this->pdo->prepare('SELECT payload FROM totp_sessions WHERE session_id = :id AND expires_at > :now');
        $statement->execute(['id' => $storageId, 'now' => time()]);
        $row = $statement->fetch();
        if (!is_array($row) || !isset($row['payload'])) {
            return '';
        }
        try {
            return reveal_value((string) $row['payload'], 'session:' . $storageId);
        } catch (Throwable $exception) {
            $this->destroy($id);
            return '';
        }
    }

    public function write(string $id, string $data): bool
    {
        $storageId = $this->storageId($id);
        $statement = $this->pdo->prepare('INSERT INTO totp_sessions (session_id, payload, expires_at)
            VALUES (:id, :payload, :expires_at)
            ON CONFLICT (session_id) DO UPDATE SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at');
        return $statement->execute([
            'id' => $storageId,
            'payload' => protect_value($data, 'session:' . $storageId),
            'expires_at' => time() + $this->lifetime,
        ]);
    }

    public function destroy(string $id): bool
    {
        $statement = $this->pdo->prepare('DELETE FROM totp_sessions WHERE session_id = :id');
        return $statement->execute(['id' => $this->storageId($id)]);
    }

    public function gc(int $max_lifetime): int|false
    {
        $statement = $this->pdo->prepare('DELETE FROM totp_sessions WHERE expires_at <= :now');
        $statement->execute(['now' => time()]);
        return $statement->rowCount();
    }
}

function app_name(): string
{
    return env_value('TOTP_APP_NAME', 'Secure Portal');
}

function admin_username(): string
{
    return env_value('TOTP_ADMIN_USER', 'admin');
}

function storage_path(): string
{
    return env_value('TOTP_STORAGE_PATH', __DIR__ . DIRECTORY_SEPARATOR . '.totp-storage.php');
}

function is_local_request(): bool
{
    if (PHP_SAPI === 'cli') {
        return true;
    }
    $remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    return $remoteAddress === '127.0.0.1' || $remoteAddress === '::1';
}

function h(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect_home(): void
{
    $requestUri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
    $path = parse_url($requestUri, PHP_URL_PATH);
    $path = is_string($path) && $path !== '' ? $path : '/';
    header('Location: ' . $path, true, 303);
    exit;
}

function initial_store(): array
{
    $configuredPassword = getenv('TOTP_ADMIN_PASSWORD');
    if ((!is_string($configuredPassword) || $configuredPassword === '') && (is_vercel_runtime() || !is_local_request())) {
        throw new RuntimeException('TOTP_ADMIN_PASSWORD wajib dikonfigurasi sebelum instalasi pertama di server publik.');
    }
    $initialPassword = is_string($configuredPassword) && $configuredPassword !== ''
        ? $configuredPassword
        : 'Admin@123';
    return [
        'version' => 1,
        'username' => admin_username(),
        'password_hash' => password_hash($initialPassword, PASSWORD_DEFAULT),
        'devices' => [],
        'created_at' => gmdate('c'),
    ];
}

function store_for_persistence(array $data): array
{
    $key = encryption_key(database_enabled());
    if (!is_string($key)) {
        return $data;
    }
    foreach ($data['devices'] as &$device) {
        if (!is_array($device) || empty($device['secret'])) {
            continue;
        }
        $secret = (string) $device['secret'];
        if (strpos($secret, 'enc:v1:') !== 0) {
            $purpose = 'totp-device:' . (string) ($device['id'] ?? 'legacy');
            $device['secret'] = protect_value($secret, $purpose);
        }
    }
    unset($device);
    return $data;
}

function store_from_persistence(array $data): array
{
    foreach ($data['devices'] as &$device) {
        if (!is_array($device) || empty($device['secret'])) {
            continue;
        }
        $purpose = 'totp-device:' . (string) ($device['id'] ?? 'legacy');
        $device['secret'] = reveal_value((string) $device['secret'], $purpose);
    }
    unset($device);
    return $data;
}

function valid_store(array $data): bool
{
    return isset($data['username'], $data['password_hash'], $data['devices']) && is_array($data['devices']);
}

function save_store(array $data): bool
{
    if (database_enabled()) {
        $pdo = database_connection();
        ensure_database_schema($pdo);
        $expectedRevision = isset($GLOBALS['store_revision']) ? (int) $GLOBALS['store_revision'] : 0;
        if ($expectedRevision < 1) {
            return false;
        }
        $json = json_encode(store_for_persistence($data), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $statement = $pdo->prepare('UPDATE totp_app_state
            SET payload = :payload, revision = revision + 1, updated_at = :updated_at
            WHERE id = 1 AND revision = :revision');
        $statement->execute([
            'payload' => $json,
            'updated_at' => time(),
            'revision' => $expectedRevision,
        ]);
        if ($statement->rowCount() !== 1) {
            return false;
        }
        $GLOBALS['store_revision'] = $expectedRevision + 1;
        return true;
    }

    $path = storage_path();
    $directory = dirname($path);
    if (!is_dir($directory) || !is_writable($directory)) {
        return false;
    }

    $json = json_encode(store_for_persistence($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return false;
    }

    $handle = @fopen($path, 'c+b');
    if ($handle === false) {
        return false;
    }

    $written = false;
    if (flock($handle, LOCK_EX)) {
        ftruncate($handle, 0);
        rewind($handle);
        $payload = STORAGE_HEADER . $json . "\n";
        $written = fwrite($handle, $payload) === strlen($payload);
        fflush($handle);
        flock($handle, LOCK_UN);
    }
    fclose($handle);
    @chmod($path, 0600);
    return $written;
}

function load_store(): array
{
    if (is_vercel_runtime() && !database_enabled()) {
        throw new RuntimeException('DATABASE_URL PostgreSQL wajib dikonfigurasi untuk deployment Vercel.');
    }

    if (database_enabled()) {
        encryption_key(true);
        $pdo = database_connection();
        ensure_database_schema($pdo);
        $statement = $pdo->query('SELECT payload, revision FROM totp_app_state WHERE id = 1');
        $row = $statement->fetch();
        if (!is_array($row)) {
            $initial = initial_store();
            $json = json_encode(store_for_persistence($initial), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $insert = $pdo->prepare('INSERT INTO totp_app_state (id, payload, revision, updated_at)
                VALUES (1, :payload, 1, :updated_at) ON CONFLICT (id) DO NOTHING');
            $insert->execute(['payload' => $json, 'updated_at' => time()]);
            if ($insert->rowCount() === 1) {
                $GLOBALS['fresh_install'] = true;
            }
            $statement = $pdo->query('SELECT payload, revision FROM totp_app_state WHERE id = 1');
            $row = $statement->fetch();
        }
        if (!is_array($row) || !isset($row['payload'], $row['revision'])) {
            throw new RuntimeException('Data aplikasi tidak dapat dibaca dari database.');
        }
        $decoded = json_decode((string) $row['payload'], true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded) || !valid_store($decoded)) {
            throw new RuntimeException('Data aplikasi di database rusak atau tidak lengkap.');
        }
        $GLOBALS['store_revision'] = (int) $row['revision'];
        return store_from_persistence($decoded);
    }

    $path = storage_path();
    if (!is_file($path)) {
        $initial = initial_store();
        if (!save_store($initial)) {
            throw new RuntimeException('Penyimpanan aplikasi tidak dapat dibuat. Pastikan folder ini bisa ditulis oleh PHP.');
        }
        $GLOBALS['fresh_install'] = true;
        return $initial;
    }

    $contents = @file_get_contents($path);
    if (!is_string($contents) || strpos($contents, STORAGE_HEADER) !== 0) {
        throw new RuntimeException('Format penyimpanan aplikasi tidak valid.');
    }

    $decoded = json_decode(substr($contents, strlen(STORAGE_HEADER)), true);
    if (!is_array($decoded) || !valid_store($decoded)) {
        throw new RuntimeException('Data aplikasi rusak atau tidak lengkap.');
    }
    return store_from_persistence($decoded);
}

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
    || is_vercel_runtime();

try {
    if (is_vercel_runtime() && !database_enabled()) {
        throw new RuntimeException('DATABASE_URL PostgreSQL wajib dikonfigurasi untuk deployment Vercel.');
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', '7200');
    session_name('native_totp_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if (database_enabled()) {
        $sessionPdo = database_connection();
        ensure_database_schema($sessionPdo);
        encryption_key(true);
        session_set_save_handler(new DatabaseSessionHandler($sessionPdo, 7200), true);
    }
    session_start();
} catch (Throwable $exception) {
    http_response_code(500);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    $safeMessage = htmlspecialchars($exception->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo '<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Kesalahan konfigurasi</title><body><main><h1>Aplikasi belum dapat dijalankan</h1><p>' . $safeMessage . '</p></main></body></html>';
    exit;
}

$cspNonce = base64_encode(random_bytes(18));
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; style-src 'nonce-{$cspNonce}'; script-src 'nonce-{$cspNonce}'");

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
    }
    return (string) $_SESSION['csrf'];
}

function csrf_is_valid(): bool
{
    $submitted = isset($_POST['csrf']) ? (string) $_POST['csrf'] : '';
    return $submitted !== '' && hash_equals(csrf_token(), $submitted);
}

function base32_encode(string $binary): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output = '';
    $buffer = 0;
    $bits = 0;

    $length = strlen($binary);
    for ($i = 0; $i < $length; $i++) {
        $buffer = ($buffer << 8) | ord($binary[$i]);
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $output .= $alphabet[($buffer >> $bits) & 31];
        }
        $buffer &= (1 << $bits) - 1;
    }
    if ($bits > 0) {
        $output .= $alphabet[($buffer << (5 - $bits)) & 31];
    }
    return $output;
}

function base32_decode(string $encoded): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $clean = strtoupper((string) preg_replace('/[^A-Z2-7]/i', '', $encoded));
    $output = '';
    $buffer = 0;
    $bits = 0;

    $length = strlen($clean);
    for ($i = 0; $i < $length; $i++) {
        $value = strpos($alphabet, $clean[$i]);
        if ($value === false) {
            continue;
        }
        $buffer = ($buffer << 5) | $value;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $output .= chr(($buffer >> $bits) & 255);
            $buffer &= (1 << $bits) - 1;
        }
    }
    return $output;
}

function new_totp_secret(): string
{
    return base32_encode(random_bytes(20));
}

function hotp(string $secret, int $counter): string
{
    $key = base32_decode($secret);
    $high = intdiv($counter, 4294967296);
    $low = $counter % 4294967296;
    $binaryCounter = pack('N2', $high, $low);
    $hash = hash_hmac('sha1', $binaryCounter, $key, true);
    $offset = ord($hash[19]) & 0x0f;
    $value = ((ord($hash[$offset]) & 0x7f) << 24)
        | ((ord($hash[$offset + 1]) & 0xff) << 16)
        | ((ord($hash[$offset + 2]) & 0xff) << 8)
        | (ord($hash[$offset + 3]) & 0xff);
    $modulo = 10 ** TOTP_DIGITS;
    return str_pad((string) ($value % $modulo), TOTP_DIGITS, '0', STR_PAD_LEFT);
}

/** Returns the accepted counter, or null when the code is invalid. */
function verify_totp(string $secret, string $code, int $window = 1): ?int
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== TOTP_DIGITS) {
        return null;
    }

    $current = intdiv(time(), TOTP_PERIOD);
    for ($offset = -$window; $offset <= $window; $offset++) {
        $counter = $current + $offset;
        if ($counter >= 0 && hash_equals(hotp($secret, $counter), $code)) {
            return $counter;
        }
    }
    return null;
}

function otpauth_uri(string $username, string $secret): string
{
    $issuer = app_name();
    $label = rawurlencode($issuer . ':' . $username);
    return 'otpauth://totp/' . $label
        . '?secret=' . rawurlencode($secret)
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=' . TOTP_DIGITS
        . '&period=' . TOTP_PERIOD;
}

function cleaned_device_name(string $name, string $fallback): string
{
    $name = trim((string) preg_replace('/\s+/', ' ', $name));
    if ($name === '') {
        return $fallback;
    }
    return function_exists('mb_substr') ? mb_substr($name, 0, 40) : substr($name, 0, 40);
}

function login_rate_limited(): bool
{
    $now = time();
    $attempts = isset($_SESSION['login_attempts']) && is_array($_SESSION['login_attempts'])
        ? $_SESSION['login_attempts']
        : [];
    $attempts = array_values(array_filter($attempts, static function ($time) use ($now): bool {
        return is_int($time) && $time > $now - 600;
    }));
    $_SESSION['login_attempts'] = $attempts;
    return count($attempts) >= 5;
}

function record_login_failure(): void
{
    if (!isset($_SESSION['login_attempts']) || !is_array($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }
    $_SESSION['login_attempts'][] = time();
}

function forget_authentication(): void
{
    unset($_SESSION['authenticated'], $_SESSION['pending_add']);
    session_regenerate_id(true);
}

$error = '';
$notice = isset($_SESSION['notice']) ? (string) $_SESSION['notice'] : '';
unset($_SESSION['notice']);
$freshInstall = !empty($GLOBALS['fresh_install']);

try {
    $store = load_store();
    $freshInstall = $freshInstall || !empty($GLOBALS['fresh_install']);
} catch (Throwable $exception) {
    http_response_code(500);
    $safeMessage = h($exception->getMessage());
    echo '<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Kesalahan konfigurasi</title><body><main><h1>Aplikasi belum dapat dijalankan</h1><p>' . $safeMessage . '</p></main></body></html>';
    exit;
}

$action = isset($_POST['action']) ? (string) $_POST['action'] : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_is_valid()) {
        http_response_code(400);
        $error = 'Sesi formulir sudah tidak valid. Muat ulang halaman lalu coba lagi.';
    } elseif ($action === 'logout') {
        forget_authentication();
        $_SESSION['notice'] = 'Anda sudah keluar dengan aman.';
        redirect_home();
    } elseif ($action === 'login') {
        if (login_rate_limited()) {
            $error = 'Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi.';
        } else {
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $credentialsOk = hash_equals((string) $store['username'], $username)
                && password_verify($password, (string) $store['password_hash']);

            if (!$credentialsOk) {
                record_login_failure();
                $error = 'Username atau password tidak sesuai.';
            } elseif (count($store['devices']) === 0) {
                unset($_SESSION['login_attempts']);
                $_SESSION['pending_enrollment'] = [
                    'secret' => new_totp_secret(),
                    'username' => (string) $store['username'],
                    'created_at' => time(),
                ];
                session_regenerate_id(true);
                redirect_home();
            } else {
                $code = (string) ($_POST['code'] ?? '');
                $matchedIndex = null;
                $matchedCounter = null;
                foreach ($store['devices'] as $index => $device) {
                    if (empty($device['secret'])) {
                        continue;
                    }
                    $counter = verify_totp((string) $device['secret'], $code);
                    $lastCounter = isset($device['last_counter']) ? (int) $device['last_counter'] : -1;
                    if ($counter !== null && $counter > $lastCounter) {
                        $matchedIndex = $index;
                        $matchedCounter = $counter;
                        break;
                    }
                }

                if ($matchedIndex === null) {
                    record_login_failure();
                    $error = 'Kode authenticator tidak valid, sudah dipakai, atau sudah kedaluwarsa.';
                } else {
                    $store['devices'][$matchedIndex]['last_counter'] = $matchedCounter;
                    $store['devices'][$matchedIndex]['last_used_at'] = gmdate('c');
                    if (!save_store($store)) {
                        $error = 'Status keamanan berubah bersamaan atau tidak dapat disimpan. Muat ulang lalu coba lagi.';
                    } else {
                        unset($_SESSION['login_attempts'], $_SESSION['pending_enrollment']);
                        session_regenerate_id(true);
                        $_SESSION['authenticated'] = true;
                        $_SESSION['notice'] = 'Login berhasil. Selamat datang kembali.';
                        redirect_home();
                    }
                }
            }
        }
    } elseif ($action === 'verify_enrollment') {
        $pending = isset($_SESSION['pending_enrollment']) && is_array($_SESSION['pending_enrollment'])
            ? $_SESSION['pending_enrollment']
            : null;
        if ($pending === null || empty($pending['secret']) || empty($pending['created_at']) || (int) $pending['created_at'] < time() - 900) {
            unset($_SESSION['pending_enrollment']);
            $error = 'Sesi pemasangan sudah kedaluwarsa. Login kembali untuk membuat QR baru.';
        } else {
            $counter = verify_totp((string) $pending['secret'], (string) ($_POST['code'] ?? ''));
            if ($counter === null) {
                $error = 'Kode 6 digit belum cocok. Pastikan waktu ponsel otomatis, lalu coba kode terbaru.';
            } else {
                $store['devices'][] = [
                    'id' => bin2hex(random_bytes(8)),
                    'name' => 'Perangkat utama',
                    'secret' => (string) $pending['secret'],
                    'created_at' => gmdate('c'),
                    'last_used_at' => null,
                    'last_counter' => -1,
                ];
                if (!save_store($store)) {
                    $error = 'Perangkat tidak dapat disimpan karena data berubah bersamaan. Muat ulang lalu coba lagi.';
                } else {
                    unset($_SESSION['pending_enrollment']);
                    session_regenerate_id(true);
                    $_SESSION['notice'] = 'Authenticator berhasil terhubung. Sekarang login ulang dengan kode 6 digit.';
                    redirect_home();
                }
            }
        }
    } elseif ($action === 'cancel_enrollment') {
        unset($_SESSION['pending_enrollment']);
        redirect_home();
    } elseif (empty($_SESSION['authenticated'])) {
        http_response_code(403);
        $error = 'Sesi login Anda berakhir. Silakan login kembali.';
    } elseif ($action === 'start_add') {
        $fallback = 'Perangkat ' . (count($store['devices']) + 1);
        $_SESSION['pending_add'] = [
            'secret' => new_totp_secret(),
            'name' => cleaned_device_name((string) ($_POST['device_name'] ?? ''), $fallback),
            'created_at' => time(),
        ];
        redirect_home();
    } elseif ($action === 'verify_add') {
        $pending = isset($_SESSION['pending_add']) && is_array($_SESSION['pending_add'])
            ? $_SESSION['pending_add']
            : null;
        if ($pending === null || empty($pending['secret']) || empty($pending['created_at']) || (int) $pending['created_at'] < time() - 900) {
            unset($_SESSION['pending_add']);
            $error = 'QR perangkat baru sudah kedaluwarsa. Buat QR baru dan coba lagi.';
        } else {
            $counter = verify_totp((string) $pending['secret'], (string) ($_POST['code'] ?? ''));
            if ($counter === null) {
                $error = 'Kode belum cocok. Masukkan kode terbaru dari perangkat yang baru dipindai.';
            } else {
                $store['devices'][] = [
                    'id' => bin2hex(random_bytes(8)),
                    'name' => cleaned_device_name((string) $pending['name'], 'Perangkat baru'),
                    'secret' => (string) $pending['secret'],
                    'created_at' => gmdate('c'),
                    'last_used_at' => null,
                    'last_counter' => -1,
                ];
                if (!save_store($store)) {
                    $error = 'Perangkat baru tidak dapat disimpan.';
                } else {
                    unset($_SESSION['pending_add']);
                    $_SESSION['notice'] = 'Perangkat baru berhasil ditambahkan.';
                    redirect_home();
                }
            }
        }
    } elseif ($action === 'cancel_add') {
        unset($_SESSION['pending_add']);
        redirect_home();
    } elseif ($action === 'revoke_device') {
        $deviceId = (string) ($_POST['device_id'] ?? '');
        if (count($store['devices']) <= 1) {
            $error = 'Perangkat terakhir tidak dapat dihapus agar akun tidak terkunci.';
        } else {
            $before = count($store['devices']);
            $store['devices'] = array_values(array_filter($store['devices'], static function (array $device) use ($deviceId): bool {
                return !isset($device['id']) || !hash_equals((string) $device['id'], $deviceId);
            }));
            if (count($store['devices']) === $before) {
                $error = 'Perangkat tidak ditemukan.';
            } elseif (!save_store($store)) {
                $error = 'Perubahan perangkat tidak dapat disimpan.';
            } else {
                $_SESSION['notice'] = 'Akses perangkat berhasil dicabut.';
                redirect_home();
            }
        }
    }
}

$isAuthenticated = !empty($_SESSION['authenticated']);
$pendingEnrollment = isset($_SESSION['pending_enrollment']) && is_array($_SESSION['pending_enrollment'])
    ? $_SESSION['pending_enrollment']
    : null;
$pendingAdd = isset($_SESSION['pending_add']) && is_array($_SESSION['pending_add'])
    ? $_SESSION['pending_add']
    : null;

if ($pendingEnrollment !== null && (!isset($pendingEnrollment['created_at']) || (int) $pendingEnrollment['created_at'] < time() - 900)) {
    unset($_SESSION['pending_enrollment']);
    $pendingEnrollment = null;
    $notice = 'QR sebelumnya sudah kedaluwarsa. Login kembali untuk membuat QR baru.';
}
if ($pendingAdd !== null && (!isset($pendingAdd['created_at']) || (int) $pendingAdd['created_at'] < time() - 900)) {
    unset($_SESSION['pending_add']);
    $pendingAdd = null;
    $notice = 'QR perangkat baru sudah kedaluwarsa. Silakan buat ulang.';
}

$showEnrollment = !$isAuthenticated && $pendingEnrollment !== null;
$showAddDevice = $isAuthenticated && $pendingAdd !== null;
$hasDevices = count($store['devices']) > 0;
$pageTitle = $isAuthenticated ? 'Dashboard' : ($showEnrollment ? 'Hubungkan authenticator' : 'Login aman');
$qrUri = '';
$qrSecret = '';
if ($showEnrollment) {
    $qrSecret = (string) $pendingEnrollment['secret'];
    $qrUri = otpauth_uri((string) $store['username'], $qrSecret);
} elseif ($showAddDevice) {
    $qrSecret = (string) $pendingAdd['secret'];
    $qrUri = otpauth_uri((string) $store['username'], $qrSecret);
}

function format_date_id(?string $date): string
{
    if (!$date) {
        return 'Belum pernah';
    }
    $timestamp = strtotime($date);
    return $timestamp === false ? '—' : gmdate('d M Y, H:i', $timestamp) . ' UTC';
}
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="color-scheme" content="light dark">
    <title><?= h($pageTitle) ?> · <?= h(app_name()) ?></title>
    <style nonce="<?= h($cspNonce) ?>">
        :root {
            color-scheme: light dark;
            font: 100%/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
            --bg: #f4f5f7;
            --surface: rgba(255, 255, 255, .78);
            --surface-solid: #fff;
            --text: #15171a;
            --muted: #6e737b;
            --line: rgba(28, 35, 45, .10);
            --line-strong: rgba(28, 35, 45, .18);
            --blue: #087af5;
            --blue-hover: #006ce0;
            --blue-soft: rgba(8, 122, 245, .11);
            --green: #198754;
            --green-soft: rgba(25, 135, 84, .12);
            --red: #d92d20;
            --red-soft: rgba(217, 45, 32, .10);
            --shadow: 0 24px 60px rgba(27, 39, 61, .13), 0 2px 10px rgba(27, 39, 61, .06);
            --radius-xl: 1.75rem;
            --radius-lg: 1.15rem;
            --radius-md: .85rem;
        }

        * { box-sizing: border-box; }
        html { min-height: 100%; }
        body {
            min-height: 100vh;
            min-height: 100svh;
            margin: 0;
            color: var(--text);
            background: var(--bg);
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
        }

        button, input { font: inherit; }
        button, .button { -webkit-tap-highlight-color: transparent; }

        .app-shell {
            width: min(100%, 72rem);
            min-height: 100vh;
            min-height: 100svh;
            margin: 0 auto;
            padding: max(1rem, env(safe-area-inset-top)) max(1rem, env(safe-area-inset-right)) max(1rem, env(safe-area-inset-bottom)) max(1rem, env(safe-area-inset-left));
            display: grid;
            place-items: center;
        }

        .auth-card {
            width: min(100%, 29rem);
            padding: clamp(1.35rem, 4vw, 2rem);
            border: 1px solid rgba(255,255,255,.68);
            border-radius: var(--radius-xl);
            background: var(--surface);
            box-shadow: var(--shadow);
            backdrop-filter: blur(28px) saturate(165%);
            -webkit-backdrop-filter: blur(28px) saturate(165%);
            animation: materialize .38s cubic-bezier(.2,.8,.2,1) both;
        }

        @keyframes materialize {
            from { opacity: 0; transform: translateY(.7rem) scale(.985); filter: blur(5px); }
            to { opacity: 1; transform: none; filter: none; }
        }

        .brand { display: flex; align-items: center; gap: .72rem; margin-bottom: 1.7rem; }
        .brand-mark {
            width: 2.45rem; height: 2.45rem; border-radius: .82rem;
            display: grid; place-items: center; color: white;
            background: var(--blue);
            box-shadow: 0 8px 18px rgba(8, 122, 245, .24), inset 0 1px 0 rgba(255,255,255,.35);
        }
        .brand-mark svg { width: 1.25rem; height: 1.25rem; }
        .brand-name { font-weight: 680; letter-spacing: -.015em; }
        .brand-kicker { display: block; color: var(--muted); font-size: .78rem; margin-top: -.1rem; }

        h1, h2, h3, p { margin-top: 0; }
        h1 { margin-bottom: .55rem; font-size: clamp(1.75rem, 5vw, 2.15rem); line-height: 1.08; letter-spacing: -.035em; font-weight: 730; }
        h2 { margin-bottom: .35rem; font-size: 1.22rem; line-height: 1.2; letter-spacing: -.02em; }
        h3 { margin-bottom: .2rem; font-size: 1rem; line-height: 1.25; }
        .lede { margin-bottom: 1.55rem; color: var(--muted); font-size: .96rem; }

        .steps { display: flex; align-items: center; gap: .35rem; margin: 0 0 1.3rem; padding: 0; list-style: none; }
        .step { height: .28rem; flex: 1; border-radius: 99px; background: var(--line-strong); }
        .step.done, .step.current { background: var(--blue); }
        .step.current { box-shadow: 0 0 0 .2rem var(--blue-soft); }

        .field { margin-bottom: 1rem; }
        .field-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
        label { display: inline-block; margin: 0 0 .42rem .12rem; font-size: .83rem; font-weight: 630; }
        .input-wrap { position: relative; }
        input[type="text"], input[type="password"] {
            width: 100%; height: 3.15rem; padding: 0 .92rem;
            color: var(--text); background: rgba(255,255,255,.68);
            border: 1px solid var(--line-strong); border-radius: var(--radius-md);
            outline: none; box-shadow: inset 0 1px 1px rgba(0,0,0,.025);
            transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
        }
        input:focus { border-color: var(--blue); box-shadow: 0 0 0 .23rem var(--blue-soft); background: var(--surface-solid); }
        input::placeholder { color: #9499a1; }
        input.otp-input { text-align: center; font-size: 1.35rem; font-weight: 700; letter-spacing: .38em; padding-left: 1.25rem; font-variant-numeric: tabular-nums; }
        .password-input { padding-right: 3.2rem !important; }
        .icon-button {
            position: absolute; inset: .38rem .42rem .38rem auto; width: 2.35rem;
            display: grid; place-items: center; border: 0; border-radius: .65rem;
            color: var(--muted); background: transparent; cursor: pointer;
        }
        .icon-button:hover { background: var(--line); color: var(--text); }
        .icon-button:active { transform: scale(.92); }
        .icon-button svg { width: 1.15rem; height: 1.15rem; }

        .button {
            width: 100%; min-height: 3.15rem; padding: .72rem 1rem;
            display: inline-flex; align-items: center; justify-content: center; gap: .48rem;
            border: 0; border-radius: var(--radius-md); text-decoration: none;
            font-weight: 670; letter-spacing: -.01em; cursor: pointer;
            transition: transform .12s ease-out, background .18s ease, box-shadow .18s ease;
        }
        .button:active { transform: scale(.975); transition-duration: .08s; }
        .button-primary { color: white; background: var(--blue); box-shadow: 0 8px 20px rgba(8,122,245,.22); }
        .button-primary:hover { background: var(--blue-hover); }
        .button-secondary { color: var(--text); background: var(--line); }
        .button-secondary:hover { background: var(--line-strong); }
        .button-ghost { width: auto; min-height: 2.55rem; color: var(--muted); background: transparent; }
        .button-ghost:hover { color: var(--text); background: var(--line); }
        .button-danger { width: auto; min-height: 2.35rem; padding: .5rem .72rem; color: var(--red); background: var(--red-soft); font-size: .82rem; }
        .button svg { width: 1.05rem; height: 1.05rem; }
        .button-row { display: flex; gap: .65rem; margin-top: 1.2rem; }
        .button-row .button { flex: 1; }

        .alert {
            margin-bottom: 1rem; padding: .78rem .9rem; display: flex; align-items: flex-start; gap: .65rem;
            border-radius: .78rem; font-size: .87rem; line-height: 1.4;
        }
        .alert svg { width: 1.05rem; height: 1.05rem; flex: 0 0 auto; margin-top: .08rem; }
        .alert-error { color: var(--red); background: var(--red-soft); }
        .alert-success { color: var(--green); background: var(--green-soft); }
        .alert-info { color: #0759aa; background: var(--blue-soft); }

        .setup-grid { display: grid; gap: 1.1rem; }
        .qr-shell {
            width: min(100%, 15.5rem); aspect-ratio: 1; margin: .2rem auto .4rem; padding: .7rem;
            display: grid; place-items: center; background: #fff; border-radius: 1.2rem;
            box-shadow: 0 10px 28px rgba(20,35,60,.10), inset 0 0 0 1px rgba(0,0,0,.06);
        }
        .qr-shell svg { width: 100%; height: 100%; display: block; }
        .qr-fallback { color: #5d6470; text-align: center; font-size: .82rem; }
        .manual-key {
            display: flex; align-items: center; gap: .55rem; padding: .7rem .75rem;
            border: 1px solid var(--line); border-radius: .78rem; background: rgba(255,255,255,.46);
        }
        .manual-key code { flex: 1; overflow-wrap: anywhere; font: 650 .77rem/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .055em; }
        .copy-button { border: 0; border-radius: .58rem; padding: .48rem .62rem; color: var(--blue); background: var(--blue-soft); font-weight: 650; cursor: pointer; }
        .copy-button:active { transform: scale(.94); }
        .hint { color: var(--muted); font-size: .8rem; }
        .divider { height: 1px; margin: 1.25rem 0; background: var(--line); }

        .dashboard-shell { width: 100%; align-self: stretch; }
        .topbar {
            position: sticky; top: max(.7rem, env(safe-area-inset-top)); z-index: 5;
            width: 100%; padding: .75rem .85rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem;
            border: 1px solid rgba(255,255,255,.62); border-radius: 1.15rem;
            background: rgba(255,255,255,.68); backdrop-filter: blur(22px) saturate(170%); -webkit-backdrop-filter: blur(22px) saturate(170%);
            box-shadow: 0 8px 28px rgba(30,45,70,.07);
        }
        .topbar .brand { margin: 0; }
        .logout-form { margin: 0; }

        .dashboard-main { padding: clamp(2rem, 6vw, 4.5rem) clamp(.2rem, 3vw, 2rem) 3rem; }
        .hero { display: flex; align-items: end; justify-content: space-between; gap: 2rem; margin-bottom: 1.7rem; }
        .hero h1 { margin-bottom: .35rem; font-size: clamp(2rem, 6vw, 3.15rem); }
        .hero p { margin: 0; color: var(--muted); }
        .status-chip {
            flex: 0 0 auto; padding: .5rem .7rem; display: inline-flex; align-items: center; gap: .42rem;
            border-radius: 99px; color: var(--green); background: var(--green-soft); font-size: .8rem; font-weight: 670;
        }
        .status-dot { width: .46rem; height: .46rem; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 .2rem rgba(25,135,84,.12); }

        .dashboard-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(16rem, .8fr); gap: 1.1rem; align-items: start; }
        .panel {
            padding: clamp(1.15rem, 3vw, 1.55rem); border: 1px solid rgba(255,255,255,.66); border-radius: var(--radius-lg);
            background: var(--surface); box-shadow: 0 14px 38px rgba(30,45,70,.07);
            backdrop-filter: blur(20px) saturate(150%); -webkit-backdrop-filter: blur(20px) saturate(150%);
        }
        .panel-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1.05rem; }
        .panel-heading p { margin: 0; color: var(--muted); font-size: .85rem; }
        .count-badge { padding: .3rem .58rem; border-radius: 99px; color: var(--blue); background: var(--blue-soft); font-size: .75rem; font-weight: 700; }
        .device-list { display: grid; gap: .65rem; }
        .device-item {
            padding: .85rem; display: flex; align-items: center; gap: .78rem;
            border: 1px solid var(--line); border-radius: .9rem; background: rgba(255,255,255,.42);
        }
        .device-icon { width: 2.5rem; height: 2.5rem; flex: 0 0 auto; display: grid; place-items: center; border-radius: .78rem; color: var(--blue); background: var(--blue-soft); }
        .device-icon svg { width: 1.22rem; height: 1.22rem; }
        .device-copy { min-width: 0; flex: 1; }
        .device-copy h3 { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .device-meta { color: var(--muted); font-size: .76rem; overflow-wrap: anywhere; }
        .device-actions form { margin: 0; }
        .add-panel form { margin-top: 1rem; }
        .add-panel-title { margin-top: .85rem; }
        .add-panel-lede { margin-bottom: 0; }
        .modal-verify-form { margin-top: 1rem; }
        .security-note { margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .79rem; }
        .security-note strong { color: var(--text); }

        .setup-overlay {
            position: fixed; inset: 0; z-index: 20; padding: max(1rem, env(safe-area-inset-top)) max(1rem, env(safe-area-inset-right)) max(1rem, env(safe-area-inset-bottom)) max(1rem, env(safe-area-inset-left));
            display: grid; place-items: center; overflow-y: auto; background: rgba(18,24,34,.34);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            animation: fade-in .22s ease-out both;
        }
        .setup-overlay .auth-card { margin: auto; }
        @keyframes fade-in { from { opacity: 0; } }

        .footer-note { margin: 1.25rem 0 0; color: var(--muted); text-align: center; font-size: .74rem; }
        .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }

        :focus-visible { outline: 3px solid color-mix(in srgb, var(--blue) 50%, transparent); outline-offset: 2px; }

        @media (max-width: 860px) {
            .dashboard-grid { grid-template-columns: 1fr; }
            .hero { align-items: flex-start; flex-direction: column; gap: 1rem; }
            .dashboard-main { padding-left: .15rem; padding-right: .15rem; }
        }
        @media (max-width: 480px) {
            .app-shell { padding: max(.7rem, env(safe-area-inset-top)) max(.7rem, env(safe-area-inset-right)) max(.7rem, env(safe-area-inset-bottom)) max(.7rem, env(safe-area-inset-left)); }
            .auth-card { padding: 1.2rem; border-radius: 1.35rem; }
            .brand { margin-bottom: 1.35rem; }
            h1 { font-size: 1.75rem; }
            .qr-shell { width: min(100%, 14rem); }
            .button-row { flex-direction: column-reverse; }
            .device-item { align-items: flex-start; flex-wrap: wrap; }
            .device-actions { width: 100%; }
            .device-actions .button { width: 100%; }
            .topbar { top: max(.45rem, env(safe-area-inset-top)); padding: .62rem .68rem; border-radius: 1rem; }
            .topbar .brand-kicker { display: none; }
            .topbar .brand-name { font-size: .9rem; }
            .topbar .brand-mark { width: 2.2rem; height: 2.2rem; }
            .topbar .button-ghost { padding-inline: .7rem; }
            .dashboard-main { padding-top: 2rem; padding-bottom: 1.5rem; }
            .hero { margin-bottom: 1.2rem; }
            .hero h1 { font-size: 2rem; }
            .panel { padding: 1rem; border-radius: 1rem; }
            .panel-heading { align-items: flex-start; }
            .manual-key { align-items: stretch; flex-direction: column; }
            .copy-button { min-height: 2.5rem; }
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #101216; --surface: rgba(31,34,41,.78); --surface-solid: #252932;
                --text: #f3f4f7; --muted: #a7abb2; --line: rgba(255,255,255,.09); --line-strong: rgba(255,255,255,.16);
                --blue: #4da2ff; --blue-hover: #70b4ff; --blue-soft: rgba(77,162,255,.14);
                --green: #54d28c; --green-soft: rgba(84,210,140,.13); --red: #ff7067; --red-soft: rgba(255,112,103,.12);
                --shadow: 0 25px 65px rgba(0,0,0,.38), 0 2px 12px rgba(0,0,0,.25);
            }
            input[type="text"], input[type="password"] { background: rgba(16,18,22,.55); }
            .auth-card, .panel, .topbar { border-color: rgba(255,255,255,.1); }
            .topbar { background: rgba(31,34,41,.7); }
            .device-item, .manual-key { background: rgba(15,17,20,.32); }
            .alert-info { color: #78b8ff; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
            .auth-card { transform: none !important; filter: none !important; }
        }
        @media (prefers-reduced-transparency: reduce) {
            .auth-card, .panel, .topbar { background: var(--surface-solid); backdrop-filter: none; -webkit-backdrop-filter: none; }
            .setup-overlay { backdrop-filter: none; -webkit-backdrop-filter: none; background: rgba(18,24,34,.72); }
        }
        @media (prefers-contrast: more) {
            :root { --line: rgba(0,0,0,.34); --line-strong: rgba(0,0,0,.6); }
            .auth-card, .panel, .topbar { background: var(--surface-solid); border: 2px solid var(--text); }
        }
    </style>
</head>
<body>
<main class="app-shell">
<?php if (!$isAuthenticated): ?>
    <section class="auth-card" aria-labelledby="page-title">
        <div class="brand">
            <span class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/><path d="M12 14v3"/></svg>
            </span>
            <span><span class="brand-name"><?= h(app_name()) ?></span><span class="brand-kicker">Two-factor authentication</span></span>
        </div>

        <?php if ($showEnrollment): ?>
            <ol class="steps" aria-label="Langkah penyiapan"><li class="step done"><span class="sr-only">Login selesai</span></li><li class="step current"><span class="sr-only">Hubungkan authenticator</span></li><li class="step"><span class="sr-only">Login ulang</span></li></ol>
            <h1 id="page-title">Hubungkan authenticator</h1>
            <p class="lede">Pindai QR dengan Google Authenticator, Microsoft Authenticator, Authy, atau aplikasi TOTP lain.</p>

            <?php if ($error): ?><div class="alert alert-error" role="alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg><span><?= h($error) ?></span></div><?php endif; ?>

            <div class="setup-grid">
                <div id="qr" class="qr-shell" data-uri="<?= h($qrUri) ?>" aria-label="QR code untuk authenticator"><span class="qr-fallback">Menyiapkan QR…</span></div>
                <div>
                    <label>Atau masukkan kunci secara manual</label>
                    <div class="manual-key"><code id="manual-key"><?= h($qrSecret) ?></code><button class="copy-button" type="button" data-copy="#manual-key">Salin</button></div>
                    <p class="hint">Tipe: berbasis waktu (TOTP) · 6 digit · setiap 30 detik</p>
                </div>
            </div>
            <div class="divider"></div>
            <form method="post" autocomplete="off">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="verify_enrollment">
                <div class="field">
                    <label for="setup-code">Masukkan kode dari aplikasi</label>
                    <input class="otp-input" id="setup-code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" required autofocus>
                </div>
                <button class="button button-primary" type="submit">Verifikasi &amp; hubungkan</button>
            </form>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="cancel_enrollment">
                <button class="button button-ghost" type="submit">Kembali ke login</button>
            </form>
        <?php else: ?>
            <ol class="steps" aria-label="Status keamanan"><li class="step current"></li><li class="step <?= $hasDevices ? 'done' : '' ?>"></li><li class="step <?= $hasDevices ? 'current' : '' ?>"></li></ol>
            <h1 id="page-title"><?= $hasDevices ? 'Selamat datang kembali' : 'Login untuk memulai' ?></h1>
            <p class="lede"><?= $hasDevices ? 'Masukkan kredensial dan kode authenticator Anda.' : 'Setelah login, Anda akan menghubungkan aplikasi authenticator.' ?></p>

            <?php if ($notice): ?><div class="alert alert-success" role="status"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/></svg><span><?= h($notice) ?></span></div><?php endif; ?>
            <?php if ($error): ?><div class="alert alert-error" role="alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg><span><?= h($error) ?></span></div><?php endif; ?>
            <?php if (!$hasDevices && ($freshInstall || (admin_username() === 'admin' && env_value('TOTP_ADMIN_PASSWORD', 'Admin@123') === 'Admin@123'))): ?>
                <div class="alert alert-info"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/></svg><span>Login awal lokal: <strong>admin</strong> / <strong>Admin@123</strong>. Ganti lewat environment variable sebelum dipakai di produksi.</span></div>
            <?php endif; ?>

            <form method="post" autocomplete="on">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="login">
                <div class="field">
                    <label for="username">Username</label>
                    <input id="username" name="username" type="text" value="<?= h((string) ($_POST['username'] ?? '')) ?>" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
                </div>
                <div class="field">
                    <label for="password">Password</label>
                    <div class="input-wrap">
                        <input class="password-input" id="password" name="password" type="password" autocomplete="current-password" required>
                        <button class="icon-button" type="button" data-toggle-password aria-label="Tampilkan password" aria-pressed="false">
                            <svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>
                        </button>
                    </div>
                </div>
                <?php if ($hasDevices): ?>
                    <div class="field">
                        <div class="field-row"><label for="login-code">Kode authenticator</label><span class="hint">6 digit</span></div>
                        <input class="otp-input" id="login-code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" required>
                    </div>
                <?php endif; ?>
                <button class="button button-primary" type="submit"><?= $hasDevices ? 'Login dengan aman' : 'Lanjutkan' ?></button>
            </form>
            <p class="footer-note">Dilindungi dengan TOTP berbasis waktu · Data tetap di server Anda</p>
        <?php endif; ?>
    </section>
<?php else: ?>
    <div class="dashboard-shell">
        <header class="topbar">
            <div class="brand">
                <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/><path d="M12 14v3"/></svg></span>
                <span><span class="brand-name"><?= h(app_name()) ?></span><span class="brand-kicker">Security dashboard</span></span>
            </div>
            <form class="logout-form" method="post">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="logout">
                <button class="button button-ghost" type="submit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10 5H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h4m5-3 4-4-4-4m4 4H9"/></svg>Keluar</button>
            </form>
        </header>

        <div class="dashboard-main">
            <div class="hero">
                <div><h1>Keamanan akun</h1><p>Kelola perangkat yang dapat menghasilkan kode login.</p></div>
                <span class="status-chip"><span class="status-dot"></span>2FA aktif</span>
            </div>

            <?php if ($notice): ?><div class="alert alert-success" role="status"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/></svg><span><?= h($notice) ?></span></div><?php endif; ?>
            <?php if ($error): ?><div class="alert alert-error" role="alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg><span><?= h($error) ?></span></div><?php endif; ?>

            <div class="dashboard-grid">
                <section class="panel" aria-labelledby="devices-title">
                    <div class="panel-heading"><div><h2 id="devices-title">Perangkat authenticator</h2><p>Kode dari perangkat berikut dapat dipakai saat login.</p></div><span class="count-badge"><?= count($store['devices']) ?> aktif</span></div>
                    <div class="device-list">
                    <?php foreach ($store['devices'] as $device): ?>
                        <article class="device-item">
                            <span class="device-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M10 5h4m-3 13.5h2"/></svg></span>
                            <div class="device-copy"><h3><?= h((string) ($device['name'] ?? 'Authenticator')) ?></h3><div class="device-meta">Ditambahkan <?= h(format_date_id(isset($device['created_at']) ? (string) $device['created_at'] : null)) ?> · Terakhir dipakai <?= h(format_date_id(isset($device['last_used_at']) ? (string) $device['last_used_at'] : null)) ?></div></div>
                            <?php if (count($store['devices']) > 1): ?>
                            <div class="device-actions">
                                <form method="post" data-confirm="Cabut akses perangkat ini? Kode dari perangkat tersebut tidak akan bisa dipakai lagi.">
                                    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="revoke_device"><input type="hidden" name="device_id" value="<?= h((string) ($device['id'] ?? '')) ?>">
                                    <button class="button button-danger" type="submit">Cabut</button>
                                </form>
                            </div>
                            <?php endif; ?>
                        </article>
                    <?php endforeach; ?>
                    </div>
                </section>

                <aside class="panel add-panel" aria-labelledby="add-title">
                    <div class="device-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg></div>
                    <h2 class="add-panel-title" id="add-title">Tambah perangkat</h2>
                    <p class="lede add-panel-lede">Hubungkan ponsel atau aplikasi authenticator cadangan.</p>
                    <form method="post">
                        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="start_add">
                        <div class="field"><label for="device-name">Nama perangkat</label><input id="device-name" name="device_name" type="text" maxlength="40" placeholder="Contoh: iPhone pribadi" required></div>
                        <button class="button button-primary" type="submit">Buat QR perangkat baru</button>
                    </form>
                    <p class="security-note"><strong>Saran:</strong> tambahkan satu perangkat cadangan agar akun tetap bisa diakses jika ponsel utama hilang.</p>
                </aside>
            </div>
        </div>
    </div>

    <?php if ($showAddDevice): ?>
    <div class="setup-overlay" role="dialog" aria-modal="true" aria-labelledby="add-device-title">
        <section class="auth-card">
            <div class="brand"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/></svg></span><span><span class="brand-name"><?= h((string) $pendingAdd['name']) ?></span><span class="brand-kicker">Perangkat baru</span></span></div>
            <h1 id="add-device-title">Pindai QR ini</h1>
            <p class="lede">Gunakan perangkat baru, lalu konfirmasi dengan kode yang muncul.</p>
            <?php if ($error): ?><div class="alert alert-error" role="alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg><span><?= h($error) ?></span></div><?php endif; ?>
            <div id="qr" class="qr-shell" data-uri="<?= h($qrUri) ?>" aria-label="QR code perangkat baru"><span class="qr-fallback">Menyiapkan QR…</span></div>
            <div class="manual-key"><code id="manual-key"><?= h($qrSecret) ?></code><button class="copy-button" type="button" data-copy="#manual-key">Salin</button></div>
            <form class="modal-verify-form" method="post" autocomplete="off">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="verify_add">
                <div class="field"><label for="add-code">Kode dari perangkat baru</label><input class="otp-input" id="add-code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" required autofocus></div>
                <button class="button button-primary" type="submit">Tambahkan perangkat</button>
            </form>
            <form method="post"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="cancel_add"><button class="button button-ghost" type="submit">Batal</button></form>
        </section>
    </div>
    <?php endif; ?>
<?php endif; ?>
</main>

<script nonce="<?= h($cspNonce) ?>">
(() => {
    'use strict';

    document.querySelectorAll('[data-toggle-password]').forEach(button => {
        button.addEventListener('click', () => {
            const input = document.getElementById('password');
            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            button.setAttribute('aria-pressed', String(!showing));
            button.setAttribute('aria-label', showing ? 'Tampilkan password' : 'Sembunyikan password');
            input.focus();
        });
    });

    document.querySelectorAll('.otp-input').forEach(input => {
        input.addEventListener('input', () => {
            input.value = input.value.replace(/\D/g, '').slice(0, 6);
        });
        input.addEventListener('paste', event => {
            const pasted = (event.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '').slice(0, 6);
            if (pasted) {
                event.preventDefault();
                input.value = pasted;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }
        });
    });

    document.querySelectorAll('[data-copy]').forEach(button => {
        button.addEventListener('click', async () => {
            const target = document.querySelector(button.dataset.copy);
            if (!target) return;
            const original = button.textContent;
            try {
                await navigator.clipboard.writeText(target.textContent.trim());
                button.textContent = 'Tersalin';
            } catch (_) {
                const range = document.createRange();
                range.selectNodeContents(target);
                const selection = window.getSelection();
                selection.removeAllRanges();
                selection.addRange(range);
                button.textContent = 'Pilih teks';
            }
            window.setTimeout(() => { button.textContent = original; }, 1500);
        });
    });

    document.querySelectorAll('[data-confirm]').forEach(form => {
        form.addEventListener('submit', event => {
            if (!window.confirm(form.dataset.confirm)) event.preventDefault();
        });
    });

    /* Self-contained QR encoder: byte mode, QR version 8-L, mask chosen by penalty. */
    class QrCode {
        constructor(text) {
            this.version = 8;
            this.size = 17 + this.version * 4;
            const bytes = Array.from(new TextEncoder().encode(text));
            if (bytes.length > 192) throw new Error('Data QR terlalu panjang');
            const data = this.makeData(bytes);
            const codewords = this.addErrorCorrection(data);
            let best = null;
            let bestPenalty = Infinity;
            for (let mask = 0; mask < 8; mask++) {
                const candidate = this.makeMatrix(codewords, mask);
                const score = this.penalty(candidate);
                if (score < bestPenalty) { bestPenalty = score; best = candidate; }
            }
            this.modules = best;
        }

        appendBits(bits, value, length) {
            for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
        }

        makeData(bytes) {
            const capacity = 194;
            const bits = [];
            this.appendBits(bits, 0b0100, 4);
            this.appendBits(bits, bytes.length, 8);
            bytes.forEach(value => this.appendBits(bits, value, 8));
            const maxBits = capacity * 8;
            for (let i = 0; i < Math.min(4, maxBits - bits.length); i++) bits.push(0);
            while (bits.length % 8) bits.push(0);
            const data = [];
            for (let i = 0; i < bits.length; i += 8) {
                let value = 0;
                for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j];
                data.push(value);
            }
            for (let pad = 0; data.length < capacity; pad++) data.push(pad % 2 === 0 ? 0xEC : 0x11);
            return data;
        }

        gfTables() {
            if (QrCode.gf) return QrCode.gf;
            const exp = new Array(512).fill(0);
            const log = new Array(256).fill(0);
            let value = 1;
            for (let i = 0; i < 255; i++) {
                exp[i] = value; log[value] = i;
                value <<= 1;
                if (value & 0x100) value ^= 0x11D;
            }
            for (let i = 255; i < 512; i++) exp[i] = exp[i - 255];
            QrCode.gf = { exp, log };
            return QrCode.gf;
        }

        multiply(a, b) {
            if (a === 0 || b === 0) return 0;
            const { exp, log } = this.gfTables();
            return exp[log[a] + log[b]];
        }

        generator(degree) {
            const { exp } = this.gfTables();
            let result = [1];
            for (let i = 0; i < degree; i++) {
                const next = new Array(result.length + 1).fill(0);
                for (let j = 0; j < result.length; j++) {
                    next[j] ^= result[j];
                    next[j + 1] ^= this.multiply(result[j], exp[i]);
                }
                result = next;
            }
            return result;
        }

        reedSolomon(data, degree) {
            const generator = this.generator(degree);
            const remainder = new Array(degree).fill(0);
            data.forEach(byte => {
                const factor = byte ^ remainder[0];
                remainder.shift(); remainder.push(0);
                for (let i = 0; i < degree; i++) remainder[i] ^= this.multiply(generator[i + 1], factor);
            });
            return remainder;
        }

        addErrorCorrection(data) {
            const blocks = [data.slice(0, 97), data.slice(97, 194)];
            const ecc = blocks.map(block => this.reedSolomon(block, 24));
            const output = [];
            for (let i = 0; i < 97; i++) blocks.forEach(block => output.push(block[i]));
            for (let i = 0; i < 24; i++) ecc.forEach(block => output.push(block[i]));
            return output;
        }

        maskBit(mask, x, y) {
            switch (mask) {
                case 0: return (x + y) % 2 === 0;
                case 1: return y % 2 === 0;
                case 2: return x % 3 === 0;
                case 3: return (x + y) % 3 === 0;
                case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
                case 5: return (x * y) % 2 + (x * y) % 3 === 0;
                case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
                default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
            }
        }

        makeMatrix(codewords, mask) {
            const modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
            const fn = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
            const setFn = (x, y, dark) => {
                if (x >= 0 && y >= 0 && x < this.size && y < this.size) {
                    modules[y][x] = Boolean(dark); fn[y][x] = true;
                }
            };
            const finder = (cx, cy) => {
                for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
                    const distance = Math.max(Math.abs(dx), Math.abs(dy));
                    setFn(cx + dx, cy + dy, distance !== 2 && distance !== 4);
                }
            };
            finder(3, 3); finder(this.size - 4, 3); finder(3, this.size - 4);
            const align = [6, 24, 42];
            align.forEach(y => align.forEach(x => {
                if (fn[y][x]) return;
                for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
                    setFn(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
                }
            }));
            for (let i = 0; i < this.size; i++) {
                if (!fn[6][i]) setFn(i, 6, i % 2 === 0);
                if (!fn[i][6]) setFn(6, i, i % 2 === 0);
            }

            let versionRemainder = this.version;
            for (let i = 0; i < 12; i++) versionRemainder = (versionRemainder << 1) ^ ((versionRemainder >>> 11) * 0x1F25);
            const versionBits = (this.version << 12) | versionRemainder;
            for (let i = 0; i < 18; i++) {
                const bit = ((versionBits >>> i) & 1) !== 0;
                const a = this.size - 11 + (i % 3);
                const b = Math.floor(i / 3);
                setFn(a, b, bit); setFn(b, a, bit);
            }

            let formatData = (1 << 3) | mask; // Error correction level L = 01
            let formatRemainder = formatData;
            for (let i = 0; i < 10; i++) formatRemainder = (formatRemainder << 1) ^ ((formatRemainder >>> 9) * 0x537);
            const formatBits = ((formatData << 10) | formatRemainder) ^ 0x5412;
            const bitAt = i => ((formatBits >>> i) & 1) !== 0;
            for (let i = 0; i <= 5; i++) setFn(8, i, bitAt(i));
            setFn(8, 7, bitAt(6)); setFn(8, 8, bitAt(7)); setFn(7, 8, bitAt(8));
            for (let i = 9; i < 15; i++) setFn(14 - i, 8, bitAt(i));
            for (let i = 0; i < 8; i++) setFn(this.size - 1 - i, 8, bitAt(i));
            for (let i = 8; i < 15; i++) setFn(8, this.size - 15 + i, bitAt(i));
            setFn(8, this.size - 8, true);

            let bitIndex = 0;
            for (let right = this.size - 1; right >= 1; right -= 2) {
                if (right === 6) right = 5;
                for (let vertical = 0; vertical < this.size; vertical++) {
                    const y = ((right + 1) & 2) === 0 ? this.size - 1 - vertical : vertical;
                    for (let offset = 0; offset < 2; offset++) {
                        const x = right - offset;
                        if (fn[y][x]) continue;
                        const byte = bitIndex >>> 3;
                        const shift = 7 - (bitIndex & 7);
                        let dark = byte < codewords.length ? ((codewords[byte] >>> shift) & 1) !== 0 : false;
                        if (this.maskBit(mask, x, y)) dark = !dark;
                        modules[y][x] = dark;
                        bitIndex++;
                    }
                }
            }
            return modules;
        }

        penalty(matrix) {
            const n = this.size;
            let score = 0;
            const linePenalty = line => {
                let value = 0;
                let runColor = line[0], run = 1;
                for (let i = 1; i < line.length; i++) {
                    if (line[i] === runColor) run++;
                    else { if (run >= 5) value += 3 + run - 5; runColor = line[i]; run = 1; }
                }
                if (run >= 5) value += 3 + run - 5;
                const binary = line.map(bit => bit ? '1' : '0').join('');
                for (let i = 0; i <= binary.length - 11; i++) {
                    const part = binary.slice(i, i + 11);
                    if (part === '00001011101' || part === '10111010000') value += 40;
                }
                return value;
            };
            for (let i = 0; i < n; i++) {
                score += linePenalty(matrix[i]);
                score += linePenalty(matrix.map(row => row[i]));
            }
            for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
                const color = matrix[y][x];
                if (matrix[y][x + 1] === color && matrix[y + 1][x] === color && matrix[y + 1][x + 1] === color) score += 3;
            }
            const dark = matrix.reduce((sum, row) => sum + row.filter(Boolean).length, 0);
            score += Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
            return score;
        }

        svg(border = 4) {
            const dimension = this.size + border * 2;
            let path = '';
            for (let y = 0; y < this.size; y++) {
                let start = null;
                for (let x = 0; x <= this.size; x++) {
                    const dark = x < this.size && this.modules[y][x];
                    if (dark && start === null) start = x;
                    if (!dark && start !== null) {
                        path += `M${start + border},${y + border}h${x - start}v1h-${x - start}z`;
                        start = null;
                    }
                }
            }
            return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dimension} ${dimension}" shape-rendering="crispEdges" role="img" aria-label="QR authenticator"><rect width="100%" height="100%" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
        }
    }

    const qrTarget = document.getElementById('qr');
    if (qrTarget && qrTarget.dataset.uri) {
        try { qrTarget.innerHTML = new QrCode(qrTarget.dataset.uri).svg(); }
        catch (error) { qrTarget.innerHTML = '<span class="qr-fallback">QR tidak dapat dibuat. Gunakan kunci manual di bawah.</span>'; }
    }
})();
</script>
</body>
</html>
