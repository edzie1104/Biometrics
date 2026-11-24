<?php
/* ═══════════════════════════════════════════════════════════════
   config/db.php — database connection + security config
   Required by auth/login.php  (defines $pdo)
   >>> EDIT the values marked CHANGE ME <<<
═══════════════════════════════════════════════════════════════ */

// ── Database ────────────────────────────────────────────────────
$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'user_login';   // CHANGE ME
$DB_USER = getenv('DB_USER') ?: 'root';                 // CHANGE ME
$DB_PASS = getenv('DB_PASS') ?: '';                     // CHANGE ME

// ── 2FA encryption key (REQUIRED) ───────────────────────────────
// Generate once:  php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
// Paste the result below. NEVER change it later (existing 2FA secrets would become unreadable).
if (!defined('MFA_ENC_KEY')) {
    define('MFA_ENC_KEY', getenv('MFA_ENC_KEY') ?: 'G1V4xu8psKvBnEzj9gfNghvnLWd/nLgimfZnG+THaAc=');   // CHANGE ME
}

// ── WebAuthn (fingerprint / passkey) ────────────────────────────────────────
// LOCAL (XAMPP): leave both lines below as they are — they auto-detect http://localhost.
// LIVE (InfinityFree, HTTPS): set the exact host you open in the browser, for example:
//     WEBAUTHN_RP_ID           = 'yourname.infinityfreeapp.com'      (no https://, no port, no slash)
//     WEBAUTHN_ALLOWED_ORIGINS = ['https://yourname.infinityfreeapp.com']
// Tip: you can instead set the environment variables WEBAUTHN_RP_ID / WEBAUTHN_ALLOWED_ORIGINS.
if (!defined('WEBAUTHN_RP_ID'))           define('WEBAUTHN_RP_ID', getenv('WEBAUTHN_RP_ID') ?: '');                  // '' = auto-detect
if (!defined('WEBAUTHN_ALLOWED_ORIGINS')) define('WEBAUTHN_ALLOWED_ORIGINS', getenv('WEBAUTHN_ALLOWED_ORIGINS') ?: ''); // '' = auto-detect (string "a,b" or array)

date_default_timezone_set('Asia/Manila');

try {
    $pdo = new PDO(
        "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
    // Keep MySQL NOW() in sync with PHP time (used by the lockout queries)
    $pdo->exec("SET time_zone = '+08:00'");
} catch (PDOException $e) {
    error_log('DB connection failed: ' . $e->getMessage());
    http_response_code(500);
    exit('Database connection failed. Check config/db.php (host, database name, user, password).');
}
