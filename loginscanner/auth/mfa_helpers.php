<?php
/* ═══════════════════════════════════════════════════════════════
   mfa_helpers.php — shared security helpers for login.php
   (CSRF, rate-limiting, TOTP, backup codes, WebAuthn glue)
═══════════════════════════════════════════════════════════════ */

if (!defined('MFA_ISSUER'))        define('MFA_ISSUER', 'Staff Monitoring');
if (!defined('AUTH_MAX_FAILS'))    define('AUTH_MAX_FAILS', 5);     // failed tries per username
if (!defined('AUTH_IP_MAX_FAILS')) define('AUTH_IP_MAX_FAILS', 25); // failed tries per IP
if (!defined('AUTH_LOCK_MINUTES')) define('AUTH_LOCK_MINUTES', 15);
if (!defined('MFA_SESSION_TTL'))   define('MFA_SESSION_TTL', 600);  // 10 min to finish step 2

/* ── Output / session ───────────────────────────────────────── */
function mfa_e($s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function mfa_is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443)
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function mfa_secure_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => mfa_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function mfa_send_security_headers(): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)');
    if (mfa_is_https()) header('Strict-Transport-Security: max-age=31536000');
}

function mfa_json(array $data, int $status = 200): void
{
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

function mfa_clear_session(): void
{
    foreach (['mfa_uid', 'mfa_expires', 'mfa_stage', 'mfa_ok', 'mfa_new_secret', 'mfa_new_codes', 'wa_challenge', 'wa_challenge_exp', 'wa_challenge_purpose'] as $k) {
        unset($_SESSION[$k]);
    }
}

/* ── CSRF ───────────────────────────────────────────────────── */
function mfa_csrf_token(): string
{
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function mfa_csrf_check($token): bool
{
    return !empty($_SESSION['csrf']) && is_string($token) && hash_equals($_SESSION['csrf'], $token);
}

/* ── Encryption of TOTP secrets at rest (AES-256-GCM) ───────────
   Define MFA_ENC_KEY (base64 of 32 random bytes) in config/db.php
   or as an environment variable.
   Generate: php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"  */
function mfa_key(): string
{
    $b64 = defined('MFA_ENC_KEY') ? MFA_ENC_KEY : (getenv('MFA_ENC_KEY') ?: '');
    $key = base64_decode((string)$b64, true);
    if ($key === false || strlen($key) !== 32) {
        error_log('MFA_ENC_KEY is missing or is not a base64-encoded 32-byte key.');
        http_response_code(500);
        exit('Server security configuration error. Contact the administrator.');
    }
    return $key;
}

function mfa_encrypt(string $plain): string
{
    $iv  = random_bytes(12);
    $tag = '';
    $ct  = openssl_encrypt($plain, 'aes-256-gcm', mfa_key(), OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ct);
}

function mfa_decrypt(string $blob): ?string
{
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 29) return null;
    $p = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', mfa_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $p === false ? null : $p;
}

/* ── Rate limiting / lockout ────────────────────────────────── */
function mfa_client_ip(): string
{
    return substr($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', 0, 45);   // never trust X-Forwarded-For here
}

function mfa_norm_user(string $u): string
{
    return mb_substr(mb_strtolower(trim($u)), 0, 100);
}

function mfa_log_attempt($pdo, string $type, string $username, ?int $userId, bool $ok): void
{
    try {
        $pdo->prepare("INSERT INTO auth_attempts (username, user_id, ip, type, success) VALUES (?,?,?,?,?)")
            ->execute([mfa_norm_user($username), $userId, mfa_client_ip(), $type, $ok ? 1 : 0]);
        if (random_int(1, 100) === 1) {
            $pdo->exec("DELETE FROM auth_attempts WHERE created_at < (NOW() - INTERVAL 2 DAY)");
        }
    } catch (Throwable $e) {
        error_log('auth_attempts log failed: ' . $e->getMessage());
    }
}

function mfa_is_locked($pdo, string $type, string $username): bool
{
    try {
        $mins = (int)AUTH_LOCK_MINUTES;
        $s = $pdo->prepare("SELECT COUNT(*) FROM auth_attempts
            WHERE type = ? AND success = 0 AND username = ?
              AND created_at > (NOW() - INTERVAL $mins MINUTE)");
        $s->execute([$type, mfa_norm_user($username)]);
        if ((int)$s->fetchColumn() >= AUTH_MAX_FAILS) return true;

        $s = $pdo->prepare("SELECT COUNT(*) FROM auth_attempts
            WHERE success = 0 AND ip = ?
              AND created_at > (NOW() - INTERVAL $mins MINUTE)");
        $s->execute([mfa_client_ip()]);
        return (int)$s->fetchColumn() >= AUTH_IP_MAX_FAILS;
    } catch (Throwable $e) {
        error_log('auth_attempts check failed: ' . $e->getMessage());
        return true;   // fail closed
    }
}

function mfa_clear_failures($pdo, string $type, string $username): void
{
    try {
        $pdo->prepare("DELETE FROM auth_attempts WHERE type = ? AND username = ? AND success = 0")
            ->execute([$type, mfa_norm_user($username)]);
    } catch (Throwable $e) {
    }
}

/* ── Base32 + TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ─────────── */
const MFA_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function mfa_b32_encode(string $bin): string
{
    $bits = '';
    foreach (str_split($bin) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split($bits, 5) as $chunk) $out .= MFA_B32[bindec(str_pad($chunk, 5, '0'))];
    return $out;
}

function mfa_b32_decode(string $s): string
{
    $s = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $s));
    if ($s === '') return '';
    $bits = '';
    foreach (str_split($s) as $c) $bits .= str_pad(decbin(strpos(MFA_B32, $c)), 5, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split($bits, 8) as $b) if (strlen($b) === 8) $out .= chr(bindec($b));
    return $out;
}

function mfa_totp_new_secret(): string
{
    return mfa_b32_encode(random_bytes(20));   // 160-bit secret
}

function mfa_totp_code(string $secretB32, int $step): string
{
    $hash = hash_hmac('sha1', pack('N2', 0, $step), mfa_b32_decode($secretB32), true);
    $o    = ord($hash[19]) & 0x0F;
    $v    = ((ord($hash[$o]) & 0x7F) << 24) | ((ord($hash[$o + 1]) & 0xFF) << 16)
          | ((ord($hash[$o + 2]) & 0xFF) << 8) | (ord($hash[$o + 3]) & 0xFF);
    return str_pad((string)($v % 1000000), 6, '0', STR_PAD_LEFT);
}

/** Returns true if the code is valid (±1 step for clock drift). $matchedStep is used to block replays. */
function mfa_totp_verify(string $secretB32, string $code, ?int &$matchedStep = null, int $window = 1): bool
{
    $code = preg_replace('/\D/', '', $code);
    if (strlen((string)$code) !== 6) return false;
    $now   = intdiv(time(), 30);
    $found = false;
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(mfa_totp_code($secretB32, $now + $i), $code)) {
            $matchedStep = $now + $i;
            $found = true;
        }
    }
    return $found;
}

function mfa_totp_uri(string $secretB32, string $account): string
{
    return 'otpauth://totp/' . rawurlencode(MFA_ISSUER . ':' . $account)
        . '?secret=' . $secretB32 . '&issuer=' . rawurlencode(MFA_ISSUER)
        . '&algorithm=SHA1&digits=6&period=30';
}

/* ── Backup (recovery) codes — stored only as HMAC hashes ───── */
function mfa_generate_backup_codes(int $n = 8): array
{
    $alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $codes = [];
    for ($i = 0; $i < $n; $i++) {
        $c = '';
        for ($j = 0; $j < 10; $j++) $c .= $alpha[random_int(0, 31)];
        $codes[] = substr($c, 0, 5) . '-' . substr($c, 5);
    }
    return $codes;
}

function mfa_backup_hash(string $code): string
{
    $c = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code));
    return hash_hmac('sha256', 'backup-code|' . $c, mfa_key());
}

function mfa_store_backup_codes($pdo, int $userId, array $codes): void
{
    $pdo->beginTransaction();
    $pdo->prepare("DELETE FROM user_backup_codes WHERE user_id = ?")->execute([$userId]);
    $ins = $pdo->prepare("INSERT INTO user_backup_codes (user_id, code_hash) VALUES (?, ?)");
    foreach ($codes as $c) $ins->execute([$userId, mfa_backup_hash($c)]);
    $pdo->commit();
}

/** Atomic single-use consume. */
function mfa_consume_backup_code($pdo, int $userId, string $code): bool
{
    if (strlen(preg_replace('/[^A-Za-z0-9]/', '', $code)) !== 10) return false;
    $s = $pdo->prepare("UPDATE user_backup_codes SET used_at = NOW()
                        WHERE user_id = ? AND code_hash = ? AND used_at IS NULL");
    $s->execute([$userId, mfa_backup_hash($code)]);
    return $s->rowCount() === 1;
}

/* ── WebAuthn (fingerprint / Face / Windows Hello) ───────────────
   Uses the lbuchs/WebAuthn library — copy its `src/` folder to
   auth/lib/WebAuthn/ (see setup notes).                           */
spl_autoload_register(function ($class) {
    $prefix = 'lbuchs\\WebAuthn\\';
    if (strpos($class, $prefix) !== 0) return;
    $file = __DIR__ . '/lib/WebAuthn/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) require_once $file;
});

function mfa_webauthn_available(): bool
{
    return PHP_VERSION_ID >= 80000
        && extension_loaded('openssl')
        && is_file(__DIR__ . '/lib/WebAuthn/WebAuthn.php')
        && is_file(__DIR__ . '/lib/WebAuthn/Binary/ByteBuffer.php');
}

function mfa_rp_id(): string
{
    // Best practice: set WEBAUTHN_RP_ID in config/db.php (or the WEBAUTHN_RP_ID environment variable).
    $id = defined('WEBAUTHN_RP_ID') ? (string)WEBAUTHN_RP_ID : '';
    if ($id === '') $id = (string)(getenv('WEBAUTHN_RP_ID') ?: '');
    if ($id === '') $id = preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? 'localhost'));
    $id = strtolower(trim($id));
    return preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/', $id) ? $id : 'localhost';
}

function mfa_webauthn()
{
    // Class name kept in a variable (and no return type) so the code loads fine
    // even if the lbuchs/WebAuthn library is not installed yet.
    $class = '\\lbuchs\\WebAuthn\\WebAuthn';
    if (!class_exists($class)) {
        throw new RuntimeException('lbuchs/WebAuthn library not found in auth/lib/WebAuthn/');
    }
    return new $class(
        MFA_ISSUER,
        mfa_rp_id(),
        ['none', 'packed', 'tpm', 'apple', 'android-key', 'fido-u2f']
    );
}

function mfa_bytebuffer(string $binary)
{
    $class = '\\lbuchs\\WebAuthn\\Binary\\ByteBuffer';
    return new $class($binary);
}

function mfa_get_credentials($pdo, int $userId): array
{
    $s = $pdo->prepare("SELECT * FROM webauthn_credentials WHERE user_id = ?");
    $s->execute([$userId]);
    return $s->fetchAll() ?: [];
}

/* ══════════════════════════════════════════════════════════════
   WebAuthn hardening: challenge expiry, origin allow-list,
   device labels, credential cap
══════════════════════════════════════════════════════════════ */
if (!defined('WA_CHALLENGE_TTL'))   define('WA_CHALLENGE_TTL', 120);   // seconds a challenge stays valid
if (!defined('WA_MAX_CREDENTIALS')) define('WA_MAX_CREDENTIALS', 10);  // devices per account

function mfa_is_local_host(string $host): bool
{
    return in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '[::1]'], true);
}

/** Origins (scheme://host[:port]) that may complete a WebAuthn ceremony. */
function mfa_allowed_origins(): array
{
    $list = [];
    if (defined('WEBAUTHN_ALLOWED_ORIGINS')) {
        $v = WEBAUTHN_ALLOWED_ORIGINS;
        $list = is_array($v) ? $v : preg_split('/[\s,]+/', (string)$v, -1, PREG_SPLIT_NO_EMPTY);
    }
    if (!$list && ($e = getenv('WEBAUTHN_ALLOWED_ORIGINS'))) {
        $list = preg_split('/[\s,]+/', (string)$e, -1, PREG_SPLIT_NO_EMPTY);
    }
    if ($list) {
        return array_values(array_map(function ($o) { return rtrim(strtolower(trim((string)$o)), '/'); }, $list));
    }
    // Default (fine for XAMPP): the origin the visitor is actually using.
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? 'localhost'));
    return [(mfa_is_https() ? 'https' : 'http') . '://' . $host];
}

/**
 * Server-side origin check on clientDataJSON (defence in depth — the library also checks the RP ID).
 * Throws when the origin is not allowed, is not HTTPS (except localhost) or does not belong to the RP ID.
 */
function mfa_wa_assert_origin(string $clientDataJSON): void
{
    $cd = json_decode($clientDataJSON, true);
    if (!is_array($cd) || !isset($cd['origin']) || !is_string($cd['origin'])) {
        throw new RuntimeException('clientDataJSON has no origin');
    }
    $origin = rtrim(strtolower($cd['origin']), '/');
    if (!in_array($origin, mfa_allowed_origins(), true)) {
        throw new RuntimeException('Origin not allowed: ' . $origin);
    }
    $p    = parse_url($origin);
    $host = (string)($p['host'] ?? '');
    if (($p['scheme'] ?? '') !== 'https' && !mfa_is_local_host($host)) {
        throw new RuntimeException('Origin is not HTTPS: ' . $origin);
    }
    $rp = mfa_rp_id();
    if ($host !== $rp && substr($host, -strlen('.' . $rp)) !== '.' . $rp) {
        throw new RuntimeException('Origin host does not match RP ID');
    }
}

/** Remember the challenge for ONE ceremony of the given purpose ('login' | 'passkey' | 'register'). */
function mfa_wa_store_challenge($wa, string $purpose): void
{
    $_SESSION['wa_challenge']         = base64_encode($wa->getChallenge()->getBinaryString());
    $_SESSION['wa_challenge_exp']     = time() + (int)WA_CHALLENGE_TTL;
    $_SESSION['wa_challenge_purpose'] = $purpose;
}

/** Returns the stored challenge (base64) exactly once; '' if missing, expired, already used or for another purpose. */
function mfa_wa_take_challenge(string $purpose): string
{
    $c   = (string)($_SESSION['wa_challenge'] ?? '');
    $exp = (int)($_SESSION['wa_challenge_exp'] ?? 0);
    $p   = (string)($_SESSION['wa_challenge_purpose'] ?? '');
    unset($_SESSION['wa_challenge'], $_SESSION['wa_challenge_exp'], $_SESSION['wa_challenge_purpose']);   // one-time use
    if ($c === '' || $exp < time() || !hash_equals($p, $purpose)) return '';
    return $c;
}

/** Stable, non-guessable WebAuthn user handle for a user id. */
function mfa_wa_user_handle(int $userId): string
{
    return hash_hmac('sha256', 'webauthn-user|' . $userId, mfa_key(), true);
}

function mfa_wa_clean_label(string $s): string
{
    $s = preg_replace('/[\x00-\x1F\x7F<>]/u', '', $s);
    return mb_substr(trim((string)$s), 0, 40);
}

/** A friendly default device name, e.g. "Windows - Chrome (2026-11-24)". */
function mfa_wa_device_label(): string
{
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (preg_match('/iPhone/i', $ua))        $os = 'iPhone';
    elseif (preg_match('/iPad/i', $ua))      $os = 'iPad';
    elseif (preg_match('/Android/i', $ua))   $os = 'Android';
    elseif (preg_match('/Windows/i', $ua))   $os = 'Windows';
    elseif (preg_match('/Mac OS X/i', $ua))  $os = 'Mac';
    elseif (preg_match('/CrOS/i', $ua))      $os = 'Chromebook';
    elseif (preg_match('/Linux/i', $ua))     $os = 'Linux';
    else                                     $os = 'Device';
    if (preg_match('/Edg(e|A|iOS)?\//i', $ua))      $br = 'Edge';
    elseif (preg_match('/OPR\/|Opera/i', $ua))      $br = 'Opera';
    elseif (preg_match('/Firefox|FxiOS/i', $ua))    $br = 'Firefox';
    elseif (preg_match('/Chrome|CriOS/i', $ua))     $br = 'Chrome';
    elseif (preg_match('/Safari/i', $ua))           $br = 'Safari';
    else                                            $br = 'Browser';
    return mfa_wa_clean_label($os . ' - ' . $br . ' (' . date('Y-m-d') . ')');
}

/** Stores a verified registration. Enforces the per-account device cap. */
function mfa_wa_save_credential($pdo, int $userId, $data, string $label): void
{
    $n = $pdo->prepare("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?");
    $n->execute([$userId]);
    if ((int)$n->fetchColumn() >= (int)WA_MAX_CREDENTIALS) {
        throw new RuntimeException('Passkey limit reached for user ' . $userId);
    }
    $pdo->prepare("INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, label) VALUES (?,?,?,?,?)")
        ->execute([
            $userId,
            base64_encode($data->credentialId),
            $data->credentialPublicKey,
            (int)($data->signatureCounter ?? 0),
            $label !== '' ? $label : 'This device',
        ]);
}
