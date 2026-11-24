<?php
/* auth/check.php — open in the browser to verify the fingerprint setup, then DELETE this file. */
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
require_once __DIR__ . '/mfa_helpers.php';
require_once __DIR__ . '/../config/db.php';

$rows = [];
function row($label, $ok, $hint = '', $warnOnly = false)
{
    global $rows;
    $rows[] = [$label, $ok, $hint, $warnOnly];
}

$isLocal   = mfa_is_local_host(preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? '')));
$libDir    = __DIR__ . '/lib/WebAuthn';

/* ── PHP environment ── */
row('PHP version ≥ 8.0', PHP_VERSION_ID >= 80000, 'Running ' . PHP_VERSION . '. InfinityFree: pick PHP 8.x in the control panel (Select PHP Version).');
row('openssl extension', extension_loaded('openssl'), 'XAMPP: enable "extension=openssl" in php.ini, then restart Apache.');
row('mbstring extension', extension_loaded('mbstring'), 'XAMPP: enable "extension=mbstring" in php.ini.');
row('Database connected', isset($pdo));

/* ── Tables / columns ── */
foreach (['users', 'app_settings', 'terms_agreements', 'user_backup_codes', 'webauthn_credentials', 'auth_attempts'] as $t) {
    try {
        $pdo->query("SELECT 1 FROM `$t` LIMIT 1");
        row("Table $t", true);
    } catch (Throwable $e) {
        row("Table $t", false, 'Run database_mfa.sql in phpMyAdmin (see the guide).');
    }
}
try {
    $c = $pdo->query("SHOW COLUMNS FROM users LIKE 'totp_enabled'")->fetch();
    row('users.totp_enabled column', (bool)$c, 'Run database_mfa.sql.');
} catch (Throwable $e) {
    row('users.totp_enabled column', false);
}

/* ── Keys ── */
$k = base64_decode(defined('MFA_ENC_KEY') ? MFA_ENC_KEY : '', true);
row('MFA_ENC_KEY valid (32 bytes)', $k !== false && strlen($k) === 32);

/* ── WebAuthn library ── */
foreach (['WebAuthn.php', 'WebAuthnException.php', 'Binary/ByteBuffer.php', 'Attestation', 'CBOR'] as $p) {
    $full = $libDir . '/' . $p;
    row("lib/WebAuthn/$p", file_exists($full), 'Copy the CONTENTS of the library\'s "src" folder into auth/lib/WebAuthn/ (keep upper/lower-case names).');
}
row('WebAuthn feature switched on (mfa_webauthn_available)', mfa_webauthn_available(), 'If this is MISSING the fingerprint button stays hidden.');
if (mfa_webauthn_available()) {
    try {
        $wa = mfa_webauthn();
        row('Library loads (class lbuchs\\WebAuthn\\WebAuthn created)', is_object($wa));
    } catch (Throwable $e) {
        row('Library loads', false, $e->getMessage());
    }
}

/* ── Origin / RP ID / HTTPS ── */
row('HTTPS (or localhost for development)', mfa_is_https() || $isLocal, 'Browsers only allow fingerprint on HTTPS (or localhost). Open the site with https://');
row('RP ID in use: ' . mfa_rp_id(), true, 'Must be your domain without http:// or port (e.g. example.com). Set WEBAUTHN_RP_ID in config/db.php for production.');
row('Allowed origin(s): ' . implode(', ', mfa_allowed_origins()), true, 'Set WEBAUTHN_ALLOWED_ORIGINS in config/db.php for production (exact https://domain).');
$explicit = (defined('WEBAUTHN_RP_ID') && WEBAUTHN_RP_ID !== '') || getenv('WEBAUTHN_RP_ID');
row('RP ID configured explicitly', (bool)$explicit || $isLocal, 'Recommended on the live site: define WEBAUTHN_RP_ID in config/db.php.', true);

/* ── Data ── */
try {
    $n = (int)$pdo->query("SELECT COUNT(*) FROM webauthn_credentials")->fetchColumn();
    row("Registered fingerprint devices: $n", true, '', true);
} catch (Throwable $e) {
}

echo '<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setup check</title>';
echo '<body style="font-family:system-ui,sans-serif;padding:20px"><h2>2FA / Fingerprint setup check</h2>';
echo '<table border="1" cellpadding="7" style="border-collapse:collapse;max-width:980px">';
foreach ($rows as [$label, $ok, $hint, $warnOnly]) {
    $col = $ok ? 'green' : ($warnOnly ? '#b45309' : 'red');
    $txt = $ok ? 'OK' : ($warnOnly ? 'WARNING' : 'MISSING');
    echo '<tr><td>' . htmlspecialchars($label) . '</td><td style="color:' . $col . '"><b>' . $txt . '</b></td><td>' . ($ok ? '' : htmlspecialchars($hint)) . '</td></tr>';
}
echo '</table><p>The QR code (authenticator setup) uses an online library (cdnjs), so the browser needs internet.</p>';
echo '<p><b>Security:</b> delete this file (auth/check.php) from the server when you are done.</p></body>';
