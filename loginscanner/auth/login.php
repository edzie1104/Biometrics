<?php
/* ═══════════════════════════════════════════════════════════════
   LOGIN — password + 2-step verification
   (Authenticator code / backup code / fingerprint via WebAuthn)
   Helpers : auth/mfa_helpers.php      Tables : auth/database_mfa.sql
═══════════════════════════════════════════════════════════════ */
require_once __DIR__ . '/mfa_helpers.php';
mfa_secure_session_start();
mfa_send_security_headers();
require_once __DIR__ . '/../config/db.php';

/** @var PDO $pdo  Created in config/db.php */
if (!isset($pdo) || !is_object($pdo)) {
    error_log('login.php: $pdo is not defined by config/db.php');
    http_response_code(500);
    exit('Database connection ($pdo) is not available. Check config/db.php.');
}

// NO chatbot widget inclusion here
if (isset($_SESSION['user_id'])) {
    redirectUser($_SESSION['role'], $_SESSION['department']);
    exit;
}

// User pressed "Cancel" while on a 2-step verification screen
if (isset($_GET['cancel'])) {
    mfa_clear_session();
    header('Location: login.php');
    exit;
}

date_default_timezone_set('Asia/Manila');
$hour        = (int)date('H');
$isRestHours = ($hour >= 23 || $hour < 5);   // 11 PM – 5 AM (Manila time)

$error = '';
if (isset($_GET['error'])) {
    switch ($_GET['error']) {
        case 'locked':
            $error = 'Too many failed attempts. Please try again in ' . AUTH_LOCK_MINUTES . ' minutes.';
            break;
        case 'csrf':
            $error = 'Your session expired. Please try again.';
            break;
        case 'mfa_invalid':
            $error = 'Invalid verification code. Please try again.';
            break;
        case 'mfa_expired':
            $error = 'Your verification session expired. Please sign in again.';
            break;
        case 'server':
            $error = 'Something went wrong. Please try again.';
            break;
        case 'empty':
            $error = 'Please enter both username and password.';
            break;
        case 'invalid':
            $error = 'Invalid username or password.';
            break;
        case 'inactive':
            $error = 'Your account is inactive. Contact the administrator.';
            break;
        case 'nodepartment':
            $error = 'No department assigned to your account.';
            break;
        case 'resthours':
            $error = 'Access restricted during rest hours (11 PM – 5 AM). Only administrators may log in at this time.';
            break;
    }
}

// ── Fetch the current active terms version ──────────────────────
function getTermsVersion($pdo): string
{
    try {
        $s = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'terms_version' LIMIT 1");
        return $s ? ($s->fetchColumn() ?: '1.0') : '1.0';
    } catch (Exception $e) {
        return '1.0';
    }
}

// ── Check whether a user has agreed to the current T&C version ──
function hasAgreedToTerms($pdo, int $userId, string $version): bool
{
    try {
        $s = $pdo->prepare("
            SELECT COUNT(*) FROM terms_agreements
            WHERE user_id = ? AND agreement_status = 'Agreed' AND terms_version = ?
            LIMIT 1
        ");
        $s->execute([$userId, $version]);
        return (int)$s->fetchColumn() > 0;
    } catch (Exception $e) {
        return false;
    }
}

$showTermsModal  = false;   // Controls whether the T&C modal auto-opens

/* ══════════════════════════════════════════════════════════════
   2-STEP VERIFICATION HELPERS
══════════════════════════════════════════════════════════════ */
function mfa_user_by_id($pdo, int $id)
{
    $s = $pdo->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
    $s->execute([$id]);
    return $s->fetch();
}

function destinationFor($role, $department = ''): string
{
    switch ($role) {
        case 'Admin':
        case 'Project Coordinator':
        case 'Admin Support':
        case 'DTR Staff':
            return '../dtr/dtr.php';
        case 'Dept Head':
        case 'Staff':
            return empty(strtolower((string)$department)) ? '' : '../dtr/dtr.php';
        default:
            return '../index.php';
    }
}

function redirectUser($role, $department = '')
{
    $dest = destinationFor($role, $department);
    if ($dest === '') {
        session_destroy();
        header('Location: login.php?error=nodepartment');
        exit;
    }
    header('Location: ' . $dest);
    exit;
}

/** Redirect (normal request) or answer with JSON (fetch request), then stop. */
function sendTo(string $url, bool $json): void
{
    if ($json) mfa_json(['success' => true, 'redirect' => $url]);
    header('Location: ' . $url);
    exit;
}

/** Returns the user that passed the password step, or ends the request if the step-2 session is invalid/expired. */
function requireMfaSession($pdo, bool $json = false): array
{
    $uid  = (int)($_SESSION['mfa_uid'] ?? 0);
    $user = ($uid > 0 && ($_SESSION['mfa_expires'] ?? 0) >= time()) ? mfa_user_by_id($pdo, $uid) : false;
    if (!$user || in_array($user['status'], ['Inactive', 'Pending'], true)) {
        mfa_clear_session();
        if ($json) {
            mfa_json(['success' => false, 'message' => 'Verification session expired. Please sign in again.', 'redirect' => 'login.php?error=mfa_expired'], 401);
        }
        header('Location: login.php?error=mfa_expired');
        exit;
    }
    return $user;
}

/** Everything is verified — start the real session (or go to the T&C gate). */
function finishLogin($pdo, array $user, bool $json = false): void
{
    mfa_clear_session();
    session_regenerate_id(true);
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    // ── Terms & Conditions gate ──────────────────────────────────
    $termsVersion = getTermsVersion($pdo);
    if (!hasAgreedToTerms($pdo, (int)$user['id'], $termsVersion)) {
        // Staging session — NOT a full login yet (terms_agreement.php completes it)
        $_SESSION['terms_pending_user_id'] = $user['id'];
        $_SESSION['terms_pending_data']    = [
            'username'   => $user['username'],
            'full_name'  => $user['full_name'],
            'role'       => $user['role'],
            'department' => $user['department'],
            'photo'      => $user['photo'] ?? '',
        ];
        sendTo('login.php', $json);   // GET login → modal auto-opens
    }

    // Already agreed — complete the login normally
    $_SESSION['user_id']    = $user['id'];
    $_SESSION['username']   = $user['username'];
    $_SESSION['full_name']  = $user['full_name'];
    $_SESSION['role']       = $user['role'];
    $_SESSION['department'] = $user['department'];
    $_SESSION['photo']      = $user['photo'] ?? '';

    $dest = destinationFor($user['role'], $user['department']);
    if ($dest === '') {
        session_destroy();
        $dest = 'login.php?error=nodepartment';
    }
    sendTo($dest, $json);
}

/** Small helper: remember something in this browser (device) only. */
function mfa_set_flag_cookie(string $name, int $days): void
{
    setcookie($name, '1', [
        'expires'  => time() + 86400 * $days,
        'path'     => '/',
        'secure'   => mfa_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

/** Called right after a second factor (or first-time enrolment) succeeds. */
function afterSecondFactor($pdo, array $user, bool $json = false): void
{
    $_SESSION['mfa_ok'] = true;
    // Offer to register this device's fingerprint (once per device; "Skip" hides the offer for 7 days)
    if (mfa_webauthn_available() && empty($_COOKIE['wa_device']) && empty($_COOKIE['wa_skip'])) {
        $_SESSION['mfa_stage'] = 'bio_offer';
        sendTo('login.php', $json);
    }
    finishLogin($pdo, $user, $json);
}

/* ══════════════════════════════════════════════════════════════
   POST HANDLER
══════════════════════════════════════════════════════════════ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    ob_start();
    $action = (string)($_POST['action'] ?? 'password');
    $isAjax = in_array($action, ['wa_login_args', 'wa_login_verify', 'wa_reg_args', 'wa_reg_verify', 'wa_passkey_args', 'wa_passkey_verify'], true);

    // ── CSRF check on every POST ─────────────────────────────────
    if (!mfa_csrf_check($_POST['csrf'] ?? null)) {
        if ($isAjax) mfa_json(['success' => false, 'message' => 'Your session expired. Please reload the page.'], 403);
        header('Location: login.php?error=csrf');
        exit;
    }

    try {
        switch ($action) {

            /* ───────── STEP 1: username + password ───────── */
            case 'password':
                $username = mb_substr(trim((string)($_POST['username'] ?? '')), 0, 100);
                $password = (string)($_POST['password'] ?? '');
                if ($username === '' || $password === '') {
                    header('Location: login.php?error=empty');
                    exit;
                }
                if (mfa_is_locked($pdo, 'password', $username)) {
                    header('Location: login.php?error=locked');
                    exit;
                }

                $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();

                // Always run password_verify (dummy hash if user not found) → no timing leak of valid usernames
                $dummyHash = '$2y$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyzABCDE';
                $valid = (password_verify($password, $user ? $user['password'] : $dummyHash) && $user);
                if (!$valid) {
                    mfa_log_attempt($pdo, 'password', $username, null, false);
                    header('Location: login.php?error=invalid');
                    exit;
                }
                mfa_clear_failures($pdo, 'password', $username);

                // Upgrade old hashes silently
                if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                    $pdo->prepare("UPDATE users SET password = ? WHERE id = ?")
                        ->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
                }

                if ($user['status'] === 'Inactive') {
                    header('Location: login.php?error=inactive');
                    exit;
                }
                if ($user['status'] === 'Pending') {
                    session_regenerate_id(true);
                    $_SESSION['pending_user_id'] = $user['id'];
                    header('Location: ../auth/first_login');
                    exit;
                }
                // ── Rest-hours guard: only Admin may log in between 11 PM and 5 AM ──
                if ($isRestHours && $user['role'] !== 'Admin') {
                    header('Location: login.php?error=resthours');
                    exit;
                }

                // Password OK → NOT logged in yet. Go to step 2.
                session_regenerate_id(true);
                mfa_clear_session();
                unset($_SESSION['terms_pending_user_id'], $_SESSION['terms_pending_data']);
                $_SESSION['mfa_uid']     = (int)$user['id'];
                $_SESSION['mfa_expires'] = time() + MFA_SESSION_TTL;
                $_SESSION['mfa_stage']   = !empty($user['totp_enabled']) ? 'verify' : 'enroll';
                header('Location: login.php');
                exit;

            /* ───────── STEP 2a: authenticator code / backup code ───────── */
            case 'verify_totp':
            case 'verify_backup':
                $user = requireMfaSession($pdo);
                if (($_SESSION['mfa_stage'] ?? '') !== 'verify') {
                    header('Location: login.php');
                    exit;
                }
                if (mfa_is_locked($pdo, 'mfa', $user['username'])) {
                    mfa_clear_session();
                    header('Location: login.php?error=locked');
                    exit;
                }
                $code = (string)($_POST['code'] ?? '');
                $ok   = false;
                if ($action === 'verify_totp') {
                    $secret = !empty($user['totp_secret']) ? mfa_decrypt($user['totp_secret']) : null;
                    $step   = null;
                    if ($secret && mfa_totp_verify($secret, $code, $step)) {
                        // Replay protection: a time-step can be used only once
                        $u = $pdo->prepare("UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)");
                        $u->execute([$step, $user['id'], $step]);
                        $ok = ($u->rowCount() === 1);
                    }
                } else {
                    $ok = mfa_consume_backup_code($pdo, (int)$user['id'], $code);
                }
                if (!$ok) {
                    mfa_log_attempt($pdo, 'mfa', $user['username'], (int)$user['id'], false);
                    header('Location: login.php?error=mfa_invalid');
                    exit;
                }
                mfa_clear_failures($pdo, 'mfa', $user['username']);
                afterSecondFactor($pdo, $user);
                exit;

            /* ───────── STEP 2b: first-time authenticator enrolment ───────── */
            case 'enroll_confirm':
                $user = requireMfaSession($pdo);
                if (($_SESSION['mfa_stage'] ?? '') !== 'enroll' || !empty($user['totp_enabled'])) {
                    mfa_clear_session();
                    header('Location: login.php');
                    exit;
                }
                if (mfa_is_locked($pdo, 'mfa', $user['username'])) {
                    mfa_clear_session();
                    header('Location: login.php?error=locked');
                    exit;
                }
                $secret = (string)($_SESSION['mfa_new_secret'] ?? '');
                $step   = null;
                if ($secret === '' || !mfa_totp_verify($secret, (string)($_POST['code'] ?? ''), $step)) {
                    mfa_log_attempt($pdo, 'mfa', $user['username'], (int)$user['id'], false);
                    header('Location: login.php?error=mfa_invalid');
                    exit;
                }
                $pdo->prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ? WHERE id = ? AND totp_enabled = 0")
                    ->execute([mfa_encrypt($secret), $step, $user['id']]);
                $codes = mfa_generate_backup_codes(8);
                mfa_store_backup_codes($pdo, (int)$user['id'], $codes);
                mfa_clear_failures($pdo, 'mfa', $user['username']);
                unset($_SESSION['mfa_new_secret']);
                $_SESSION['mfa_new_codes'] = $codes;
                $_SESSION['mfa_ok']        = true;
                $_SESSION['mfa_stage']     = 'codes';
                header('Location: login.php');
                exit;

            /* ───────── Backup codes were saved ───────── */
            case 'codes_ack':
                $user = requireMfaSession($pdo);
                if (empty($_SESSION['mfa_ok']) || ($_SESSION['mfa_stage'] ?? '') !== 'codes') {
                    header('Location: login.php');
                    exit;
                }
                unset($_SESSION['mfa_new_codes']);
                afterSecondFactor($pdo, $user);
                exit;

            /* ───────── Fingerprint offer: continue / skip ───────── */
            case 'bio_continue':
                $user = requireMfaSession($pdo);
                if (empty($_SESSION['mfa_ok']) || ($_SESSION['mfa_stage'] ?? '') !== 'bio_offer') {
                    header('Location: login.php');
                    exit;
                }
                if (($_POST['skip'] ?? '') === '1') mfa_set_flag_cookie('wa_skip', 7);
                finishLogin($pdo, $user);
                exit;

            /* ───────── FINGERPRINT SIGN-IN (WebAuthn assertion) ───────── */
            case 'wa_login_args':
                $user = requireMfaSession($pdo, true);
                if (($_SESSION['mfa_stage'] ?? '') !== 'verify' || !mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint sign-in is not available.'], 400);
                }
                if (mfa_is_locked($pdo, 'mfa', $user['username'])) {
                    mfa_clear_session();
                    mfa_json(['success' => false, 'message' => 'Too many failed attempts.', 'redirect' => 'login.php?error=locked'], 429);
                }
                $ids = [];
                foreach (mfa_get_credentials($pdo, (int)$user['id']) as $r) $ids[] = base64_decode($r['credential_id']);
                if (!$ids) mfa_json(['success' => false, 'message' => 'No fingerprint registered for this account.'], 400);

                $wa   = mfa_webauthn();
                $args = $wa->getGetArgs($ids, 60, requireUserVerification: true);
                mfa_wa_store_challenge($wa, 'login');
                mfa_json(['success' => true, 'args' => $args]);

            case 'wa_login_verify':
                $user = requireMfaSession($pdo, true);
                if (($_SESSION['mfa_stage'] ?? '') !== 'verify' || !mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint sign-in is not available.'], 400);
                }
                if (mfa_is_locked($pdo, 'mfa', $user['username'])) {
                    mfa_clear_session();
                    mfa_json(['success' => false, 'message' => 'Too many failed attempts.', 'redirect' => 'login.php?error=locked'], 429);
                }
                $clientDataJSON    = base64_decode((string)($_POST['clientDataJSON'] ?? ''), true);
                $authenticatorData = base64_decode((string)($_POST['authenticatorData'] ?? ''), true);
                $signature         = base64_decode((string)($_POST['signature'] ?? ''), true);
                $credId            = base64_decode((string)($_POST['id'] ?? ''), true);
                $challengeB64      = mfa_wa_take_challenge('login');   // one-time + expires after WA_CHALLENGE_TTL s

                $row = null;
                if ($credId !== false) {
                    foreach (mfa_get_credentials($pdo, (int)$user['id']) as $r) {
                        if (hash_equals((string)$r['credential_id'], base64_encode($credId))) {
                            $row = $r;
                            break;
                        }
                    }
                }
                $ok = false;
                if ($row && $clientDataJSON !== false && $authenticatorData !== false && $signature !== false && $challengeB64 !== '') {
                    try {
                        mfa_wa_assert_origin($clientDataJSON);   // origin must be on the allow-list
                        $wa   = mfa_webauthn();
                        $prev = (int)$row['sign_count'];
                        $wa->processGet(
                            $clientDataJSON,
                            $authenticatorData,
                            $signature,
                            $row['public_key'],
                            mfa_bytebuffer(base64_decode($challengeB64)),
                            $prev > 0 ? $prev : null,
                            true,   // require user verification (fingerprint / face / PIN on the device)
                            true    // require user presence
                        );
                        $ok     = true;
                        $newCnt = $wa->getSignatureCounter();
                        $pdo->prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = NOW() WHERE id = ?")
                            ->execute([is_int($newCnt) ? $newCnt : $prev, $row['id']]);
                    } catch (Throwable $e) {
                        error_log('WebAuthn assertion failed: ' . $e->getMessage());
                    }
                }
                mfa_log_attempt($pdo, 'mfa', $user['username'], (int)$user['id'], $ok);
                if (!$ok) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint verification failed. Use your authenticator code instead.'], 401);
                }
                mfa_clear_failures($pdo, 'mfa', $user['username']);
                afterSecondFactor($pdo, $user, true);
                exit;

            /* ───────── FINGERPRINT REGISTRATION (WebAuthn attestation) ───────── */
            case 'wa_reg_args':
                $user = requireMfaSession($pdo, true);
                if (empty($_SESSION['mfa_ok']) || ($_SESSION['mfa_stage'] ?? '') !== 'bio_offer' || !mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Not available.'], 400);
                }
                $exclude = [];   // allow re-registering on this device so it becomes a passkey
                $userHandle = mfa_wa_user_handle((int)$user['id']);

                $wa   = mfa_webauthn();
                $args = $wa->getCreateArgs(
                    $userHandle,
                    (string)$user['username'],
                    (string)($user['full_name'] ?: $user['username']),
                    60,
                    true,    // discoverable credential (passkey) -> user can sign in with just a fingerprint
                    true,    // require user verification (biometric)
                    false,   // platform authenticator only (built-in fingerprint / Face ID / Windows Hello)
                    $exclude
                );
                mfa_wa_store_challenge($wa, 'register');
                mfa_json(['success' => true, 'args' => $args]);

            case 'wa_reg_verify':
                $user = requireMfaSession($pdo, true);
                if (empty($_SESSION['mfa_ok']) || ($_SESSION['mfa_stage'] ?? '') !== 'bio_offer' || !mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Not available.'], 400);
                }
                $clientDataJSON    = base64_decode((string)($_POST['clientDataJSON'] ?? ''), true);
                $attestationObject = base64_decode((string)($_POST['attestationObject'] ?? ''), true);
                $challengeB64      = mfa_wa_take_challenge('register');   // one-time + expires after WA_CHALLENGE_TTL s
                if ($clientDataJSON === false || $attestationObject === false || $challengeB64 === '') {
                    mfa_json(['success' => false, 'message' => 'Invalid registration data.'], 400);
                }
                try {
                    mfa_wa_assert_origin($clientDataJSON);   // origin must be on the allow-list
                    $wa   = mfa_webauthn();
                    $data = $wa->processCreate(
                        $clientDataJSON,
                        $attestationObject,
                        mfa_bytebuffer(base64_decode($challengeB64)),
                        true,    // require user verification
                        true,    // require user presence
                        false,   // don't fail on unknown attestation root (platform authenticators)
                        false
                    );
                    mfa_wa_save_credential($pdo, (int)$user['id'], $data, mfa_wa_device_label());
                    mfa_set_flag_cookie('wa_device', 365);
                    mfa_json(['success' => true]);
                } catch (Throwable $e) {
                    error_log('WebAuthn registration failed: ' . $e->getMessage());
                    mfa_json(['success' => false, 'message' => 'Could not register this device. You can still sign in with your authenticator app.'], 400);
                }

            /* ───────── FINGERPRINT SIGN-IN FROM THE LOGIN SCREEN (no username / password) ───────── */
            case 'wa_passkey_args':
                if (!mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint sign-in is not available on this server.'], 400);
                }
                if (mfa_is_locked($pdo, 'mfa', 'passkey@' . mfa_client_ip())) {
                    mfa_json(['success' => false, 'message' => 'Too many failed attempts. Please wait a few minutes.'], 429);
                }
                $wa   = mfa_webauthn();
                $args = $wa->getGetArgs([], 60, requireUserVerification: true);   // empty list = any saved passkey
                mfa_wa_store_challenge($wa, 'passkey');
                mfa_json(['success' => true, 'args' => $args]);

            case 'wa_passkey_verify':
                if (!mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint sign-in is not available on this server.'], 400);
                }
                $pkKey = 'passkey@' . mfa_client_ip();
                if (mfa_is_locked($pdo, 'mfa', $pkKey)) {
                    mfa_json(['success' => false, 'message' => 'Too many failed attempts. Please wait a few minutes.'], 429);
                }
                $clientDataJSON    = base64_decode((string)($_POST['clientDataJSON'] ?? ''), true);
                $authenticatorData = base64_decode((string)($_POST['authenticatorData'] ?? ''), true);
                $signature         = base64_decode((string)($_POST['signature'] ?? ''), true);
                $credId            = base64_decode((string)($_POST['id'] ?? ''), true);
                $userHandle        = base64_decode((string)($_POST['userHandle'] ?? ''), true);
                $challengeB64      = mfa_wa_take_challenge('passkey');   // one-time + expires after WA_CHALLENGE_TTL s

                $row  = null;
                $user = null;
                if ($credId !== false && $credId !== '') {
                    $q = $pdo->prepare("SELECT * FROM webauthn_credentials WHERE credential_id = ? LIMIT 1");
                    $q->execute([base64_encode($credId)]);
                    $row = $q->fetch() ?: null;
                    if ($row) $user = mfa_user_by_id($pdo, (int)$row['user_id']) ?: null;
                }

                $ok  = false;
                $msg = 'Fingerprint sign-in failed. Please sign in with your username and password.';
                if ($row && $user && $clientDataJSON !== false && $authenticatorData !== false && $signature !== false && $challengeB64 !== '') {
                    try {
                        mfa_wa_assert_origin($clientDataJSON);   // origin must be on the allow-list
                        $wa   = mfa_webauthn();
                        $prev = (int)$row['sign_count'];
                        $wa->processGet(
                            $clientDataJSON,
                            $authenticatorData,
                            $signature,
                            $row['public_key'],
                            mfa_bytebuffer(base64_decode($challengeB64)),
                            $prev > 0 ? $prev : null,
                            true,   // require user verification (fingerprint / face / PIN)
                            true    // require user presence
                        );
                        $ok = true;
                        // the passkey must belong to the user it claims to belong to
                        if ($userHandle !== false && $userHandle !== '') {
                            $expected = mfa_wa_user_handle((int)$user['id']);
                            if (!hash_equals($expected, $userHandle)) $ok = false;
                        }
                        if ($ok) {
                            $newCnt = $wa->getSignatureCounter();
                            $pdo->prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = NOW() WHERE id = ?")
                                ->execute([is_int($newCnt) ? $newCnt : $prev, $row['id']]);
                        }
                    } catch (Throwable $e) {
                        $ok = false;
                        error_log('Passkey assertion failed: ' . $e->getMessage());
                    }
                }
                if (!$ok) {
                    mfa_log_attempt($pdo, 'mfa', $pkKey, null, false);
                    mfa_json(['success' => false, 'message' => $msg], 401);
                }

                // Same account rules as the password login
                if ($user['status'] === 'Inactive') {
                    mfa_json(['success' => false, 'message' => 'This account is inactive.'], 403);
                }
                if ($user['status'] === 'Pending') {
                    mfa_json(['success' => false, 'message' => 'Please sign in with your password first to finish setting up your account.'], 403);
                }
                if ($isRestHours && $user['role'] !== 'Admin') {
                    mfa_json(['success' => false, 'message' => 'Sign-in is not available during rest hours (11 PM - 5 AM).'], 403);
                }

                mfa_clear_failures($pdo, 'mfa', $pkKey);
                mfa_log_attempt($pdo, 'mfa', $user['username'], (int)$user['id'], true);
                finishLogin($pdo, $user, true);
                exit;

            default:
                header('Location: login.php');
                exit;
        }
    } catch (Throwable $e) {
        error_log('login.php error: ' . $e->getMessage());
        if ($isAjax) mfa_json(['success' => false, 'message' => 'Something went wrong. Please try again.'], 500);
        header('Location: login.php?error=server');
        exit;
    }
}

/* ══════════════════════════════════════════════════════════════
   WHICH SCREEN ARE WE ON? (GET)
══════════════════════════════════════════════════════════════ */
$stage        = 'login';
$mfaUser      = null;
$hasBio       = false;
$enrollSecret = '';
$enrollUri    = '';
$backupCodes  = [];

if (!empty($_SESSION['mfa_uid'])) {
    $mfaUser = requireMfaSession($pdo);   // validates expiry + account status
    $stage   = (string)($_SESSION['mfa_stage'] ?? 'verify');
    if (!in_array($stage, ['verify', 'enroll', 'codes', 'bio_offer'], true)) $stage = 'login';

    if ($stage === 'enroll') {
        if (empty($_SESSION['mfa_new_secret'])) $_SESSION['mfa_new_secret'] = mfa_totp_new_secret();
        $enrollSecret = $_SESSION['mfa_new_secret'];
        $enrollUri    = mfa_totp_uri($enrollSecret, $mfaUser['username']);
    } elseif ($stage === 'verify') {
        $hasBio = mfa_webauthn_available() && count(mfa_get_credentials($pdo, (int)$mfaUser['id'])) > 0;
    } elseif ($stage === 'codes') {
        $backupCodes = $_SESSION['mfa_new_codes'] ?? [];
    }
}

$subLines = [
    'login'     => 'Sign in to access your workspace.',
    'verify'    => 'Two-step verification — enter the 6-digit code from your authenticator app.',
    'enroll'    => 'One-time setup: secure your account with two-step verification.',
    'codes'     => 'Two-step verification is on. Save your backup codes.',
    'bio_offer' => 'Optional: sign in faster with your fingerprint.',
];
$subLine = $subLines[$stage] ?? $subLines['login'];

// ── Also auto-open the modal if the session is mid-agreement ────
if (!$showTermsModal && !empty($_SESSION['terms_pending_user_id'])) {
    $showTermsModal = true;
}
$termsVersion = getTermsVersion($pdo);

$hour = (int)date('H');
if ($hour >= 5  && $hour < 12) $tc = 'morning';
elseif ($hour >= 12 && $hour < 17) $tc = 'afternoon';
elseif ($hour >= 17 && $hour < 21) $tc = 'evening';
else $tc = 'night';
?>
<!DOCTYPE html>
<html lang="en" data-period="<?= $tc ?>">

<head>
    <meta charset="UTF-8">
    <link rel="icon" type="image/png" sizes="128x128" href="../unbound.png">
    <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
    <title>Sign In — Staff Monitoring</title>


    <link rel="preconnect" href="https://fonts.googleapis.com">

    <link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
    <style>
        /* ══════════════════════════════════════
   BASE
══════════════════════════════════════ */
        *,
        *::before,
        *::after {
            margin: 0;
            padding: 0;
            box-sizing: border-box
        }

        html,
        body {
            height: 100%
        }

        :root {
            --ff-h: 'Sora', sans-serif;
            --ff-b: 'DM Sans', sans-serif;
            --ease: cubic-bezier(.22, 1, .36, 1);
        }

        .topbar {
            display: none !important;
        }

        body {
            min-height: 100vh;
            min-height: 100dvh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--ff-b);
            padding: 1.5rem;
            overflow-x: hidden;
            overflow-y: auto;
            position: relative;
            background: #0d1b2a;
        }

        /* CSS fallback sky — canvas draws on top but this shows on load */
        [data-period=morning] body {
            background: linear-gradient(to bottom, #f7a8b8 0%, #f9c9b6 30%, #fad5b1 55%, #9cdbff 75%, #e9f6ff 100%);
        }

        [data-period=afternoon] body {
            background: linear-gradient(to bottom, #1e90ff 0%, #4facfe 35%, #82c5ff 55%, #bce3ff 75%, #f0f9ff 100%);
        }

        [data-period=evening] body {
            background: linear-gradient(to bottom, #ff9a56 0%, #ff6b6b 30%, #c44d8b 55%, #5b2c6c 75%, #1b1c3a 100%);
        }

        [data-period=night] body {
            background: linear-gradient(to bottom, #0b0c1e 0%, #141852 35%, #2c2f7a 60%, #1b3b6f 80%, #0d1b2a 100%);
        }

        /* ══════════════════════════════════════
   CANVAS — full environment, behind everything
══════════════════════════════════════ */
        #envCanvas {
            position: fixed;
            inset: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            display: block;
        }

        /* ══════════════════════════════════════
   OVERLAY LAYERS
══════════════════════════════════════ */
        /* deep cinematic vignette */
        #vignette {
            position: fixed;
            inset: 0;
            z-index: 1;
            pointer-events: none;
            background:
                radial-gradient(ellipse 110% 110% at 50% 50%,
                    transparent 32%, rgba(0, 0, 0, .20) 62%, rgba(0, 0, 0, .68) 100%),
                linear-gradient(0deg, rgba(0, 0, 0, .32) 0%, transparent 38%);
        }

        /* analog film grain */
        #grain {
            position: fixed;
            inset: 0;
            z-index: 2;
            pointer-events: none;
            opacity: .032;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
            background-size: 256px;
            animation: grainAnim .09s steps(1) infinite;
        }

        @keyframes grainAnim {
            0% {
                background-position: 0 0
            }

            10% {
                background-position: -70px 40px
            }

            20% {
                background-position: 40px -80px
            }

            30% {
                background-position: -110px 22px
            }

            40% {
                background-position: 55px 95px
            }

            50% {
                background-position: -38px -55px
            }

            60% {
                background-position: 90px 72px
            }

            70% {
                background-position: -58px 112px
            }

            80% {
                background-position: 75px -38px
            }

            90% {
                background-position: -90px 55px
            }

            100% {
                background-position: 0 0
            }
        }

        /* firefly container */
        #ffLayer {
            position: fixed;
            inset: 0;
            z-index: 2;
            pointer-events: none;
            overflow: hidden
        }

        /* ══════════════════════════════════════
   LOGIN CARD
══════════════════════════════════════ */
        #loginWrap {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 448px;
            margin: auto;
        }

        .card {
            border-radius: 28px;
            overflow: hidden;
            animation: cardIn 1.1s var(--ease) both;
            box-shadow:
                0 0 0 1px rgba(255, 255, 255, .10),
                0 2px 0 1px rgba(255, 255, 255, .20),
                0 8px 32px rgba(0, 0, 0, .22),
                0 24px 72px rgba(0, 0, 0, .32),
                0 64px 128px rgba(0, 0, 0, .22);
            transition: transform .12s ease, box-shadow .12s ease;
            will-change: transform;
        }

        @keyframes cardIn {
            0% {
                opacity: 0;
                transform: translateY(64px) scale(.92) rotateX(5deg)
            }

            65% {
                opacity: 1;
                transform: translateY(-5px) scale(1.006)
            }

            100% {
                opacity: 1;
                transform: translateY(0) scale(1) rotateX(0)
            }
        }

        /* ── TOP BAR ── */
        .topbar {
            position: relative;
            overflow: hidden;
            padding: 15px 22px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .tbar-l {
            display: flex;
            align-items: center;
            gap: 9px
        }

        .tbar-clock {
            font-family: var(--ff-h);
            font-size: .9rem;
            font-weight: 600;
            color: #fff;
            letter-spacing: .05em;
            text-shadow: 0 1px 6px rgba(0, 0, 0, .45);
        }

        .tbar-badge {
            font-family: var(--ff-h);
            font-size: .64rem;
            font-weight: 700;
            letter-spacing: .10em;
            text-transform: uppercase;
            background: rgba(255, 255, 255, .16);
            border: 1px solid rgba(255, 255, 255, .28);
            border-radius: 99px;
            padding: 3px 10px;
            color: #fff;
            backdrop-filter: blur(4px);
        }

        /* shimmer sweep */
        .topbar::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, transparent 0%, rgba(255, 255, 255, .15) 50%, transparent 100%);
            transform: translateX(-100%);
            animation: tbShimmer 3.8s ease-in-out infinite;
        }

        @keyframes tbShimmer {
            0% {
                transform: translateX(-100%)
            }

            60% {
                transform: translateX(130%)
            }

            100% {
                transform: translateX(130%)
            }
        }

        [data-period=morning] .topbar {
            background: linear-gradient(112deg, #7f1d00, #c2410c, #ea580c, #fb923c)
        }

        [data-period=afternoon] .topbar {
            background: linear-gradient(112deg, #0c4a6e, #0369a1, #0284c7, #38bdf8)
        }

        [data-period=evening] .topbar {
            background: linear-gradient(112deg, #1e1b4b, #3730a3, #7c3aed, #a855f7)
        }

        [data-period=night] .topbar {
            background: linear-gradient(112deg, #0f172a, #1e1b4b, #312e81, #4338ca)
        }

        /* pulse online indicator */
        .online-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            flex-shrink: 0;
            background: #4ade80;
            box-shadow: 0 0 0 0 rgba(74, 222, 128, .6);
            animation: pulseDot 2.2s ease-in-out infinite;
        }

        @keyframes pulseDot {
            0% {
                box-shadow: 0 0 0 0 rgba(74, 222, 128, .65)
            }

            70% {
                box-shadow: 0 0 0 6px rgba(74, 222, 128, 0)
            }

            100% {
                box-shadow: 0 0 0 0 rgba(74, 222, 128, 0)
            }
        }

        /* ── CARD BODY ── */
        .card-body {
            padding: 2.2rem 2.5rem 2.5rem;
            position: relative;
            overflow: hidden
        }

        /* inner texture */
        .card-body::before {
            content: '';
            position: absolute;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            opacity: .022;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.75' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
            background-size: 200px;
        }

        .card-body>* {
            position: relative;
            z-index: 1;
        }

        [data-period=morning] .card-body,
        [data-period=afternoon] .card-body {
            background: rgba(255, 255, 255, .76);
            backdrop-filter: blur(44px) saturate(1.7) brightness(1.06);
            -webkit-backdrop-filter: blur(44px) saturate(1.7) brightness(1.06);
            border: 1px solid rgba(255, 255, 255, .72);
            border-top: none;
        }

        [data-period=evening] .card-body,
        [data-period=night] .card-body {
            background: rgba(4, 8, 26, .88);
            backdrop-filter: blur(44px) saturate(1.6);
            -webkit-backdrop-filter: blur(44px) saturate(1.6);
            border: 1px solid rgba(255, 255, 255, .08);
            border-top: none;
        }

        /* inner glow for dark mode */
        [data-period=evening] .card-body::after,
        [data-period=night] .card-body::after {
            content: '';
            position: absolute;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            border-radius: 0 0 28px 28px;
            box-shadow: inset 0 0 90px rgba(99, 102, 241, .055);
        }

        /* stagger entrance */
        .card-body>* {
            animation: stUp .62s var(--ease) both
        }

        .card-body>*:nth-child(1) {
            animation-delay: .10s
        }

        .card-body>*:nth-child(2) {
            animation-delay: .18s
        }

        .card-body>*:nth-child(3) {
            animation-delay: .26s
        }

        .card-body>*:nth-child(4) {
            animation-delay: .34s
        }

        .card-body>*:nth-child(5) {
            animation-delay: .42s
        }

        .card-body>*:nth-child(6) {
            animation-delay: .50s
        }

        .card-body>*:nth-child(7) {
            animation-delay: .58s
        }

        @keyframes stUp {
            from {
                opacity: 0;
                transform: translateY(24px) scale(.97)
            }

            to {
                opacity: 1;
                transform: translateY(0) scale(1)
            }
        }

        /* ── LOGO ZONE ── */
        .logo-zone {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            margin-bottom: 1.4rem;
        }

        .logo-wrap {
            display: flex;
            align-items: center;
            justify-content: center;
        }






        @keyframes logoFloat {

            0%,
            100% {
                transform: translateY(0)
            }

            50% {
                transform: translateY(-9px)
            }
        }

        .logo-img {
            width: 54px;
            height: 54px;
            object-fit: contain;
            filter: drop-shadow(0 4px 10px rgba(0, 0, 0, .22))
        }

        [data-period=evening] .logo-img,
        [data-period=night] .logo-img {
            filter: drop-shadow(0 4px 14px rgba(129, 140, 248, .5)) brightness(1.18)
        }

        .brand-name {
            font-family: var(--ff-h);
            font-size: 1.68rem;
            font-weight: 800;
            letter-spacing: -.045em;
            line-height: 1
        }

        [data-period=morning] .brand-name {
            color: #431407
        }

        [data-period=morning] .brand-name em {
            color: #ea580c;
            font-style: normal
        }

        [data-period=afternoon] .brand-name {
            color: #0c2d4a
        }

        [data-period=afternoon] .brand-name em {
            color: #0284c7;
            font-style: normal
        }

        [data-period=evening] .brand-name {
            color: #e2e8f0
        }

        [data-period=evening] .brand-name em {
            color: #c084fc;
            font-style: normal
        }

        [data-period=night] .brand-name {
            color: #f1f5f9
        }

        [data-period=night] .brand-name em {
            color: #818cf8;
            font-style: normal
        }

        .brand-sub {
            font-size: .70rem;
            font-weight: 500;
            letter-spacing: .12em;
            text-transform: uppercase;
            margin-top: 5px;
            opacity: .50
        }

        [data-period=morning] .brand-sub,
        [data-period=afternoon] .brand-sub {
            color: #334155
        }

        [data-period=evening] .brand-sub,
        [data-period=night] .brand-sub {
            color: #94a3b8
        }

        /* ── GREETING ── */
        .greeting {
            display: flex;
            align-items: center;
            gap: 11px;
            margin-bottom: 4px
        }

        .g-icon {
            font-size: 2.1rem;
            line-height: 1;
            animation: gBob 4s ease-in-out infinite
        }

        @keyframes gBob {

            0%,
            100% {
                transform: scale(1) translateY(0)
            }

            42% {
                transform: scale(1.09) translateY(-4px)
            }
        }

        .g-text {
            font-family: var(--ff-h);
            font-size: 1.68rem;
            font-weight: 700;
            line-height: 1.15
        }

        [data-period=morning] .g-text {
            color: #7c2d12
        }

        [data-period=afternoon] .g-text {
            color: #0c4a6e
        }

        [data-period=evening] .g-text,
        [data-period=night] .g-text {
            color: #f8fafc
        }

        .sub-line {
            font-size: .86rem;
            margin-bottom: 1.55rem;
            line-height: 1.5;
            opacity: .60
        }

        [data-period=morning] .sub-line,
        [data-period=afternoon] .sub-line {
            color: #1e3a4a
        }

        [data-period=evening] .sub-line,
        [data-period=night] .sub-line {
            color: #94a3b8
        }

        /* ── DIVIDER ── */
        .hdivider {
            height: 1px;
            margin: 0 -2.5rem 1.55rem;
            opacity: .28
        }

        [data-period=morning] .hdivider {
            background: linear-gradient(90deg, transparent, #fb923c, transparent)
        }

        [data-period=afternoon] .hdivider {
            background: linear-gradient(90deg, transparent, #38bdf8, transparent)
        }

        [data-period=evening] .hdivider {
            background: linear-gradient(90deg, transparent, #a855f7, transparent)
        }

        [data-period=night] .hdivider {
            background: linear-gradient(90deg, transparent, #818cf8, transparent)
        }

        /* ── ERROR ── */
        .err {
            display: flex;
            align-items: center;
            gap: 9px;
            border-radius: 12px;
            padding: .80rem 1.1rem;
            margin-bottom: 1.1rem;
            font-size: .875rem;
            background: rgba(239, 68, 68, .10);
            border: 1px solid rgba(239, 68, 68, .28);
            color: #dc2626;
            animation: shake .5s cubic-bezier(.36, .07, .19, .97);
        }

        @keyframes shake {

            0%,
            100% {
                transform: translateX(0)
            }

            14% {
                transform: translateX(-7px)
            }

            28% {
                transform: translateX(6px)
            }

            42% {
                transform: translateX(-4px)
            }

            56% {
                transform: translateX(3px)
            }
        }

        [data-period=evening] .err,
        [data-period=night] .err {
            background: rgba(239, 68, 68, .16);
            color: #fca5a5
        }

        /* ── REST HOURS BANNER ── */
        .rest-banner {
            display: flex;
            flex-direction: column;
            gap: .55rem;
            border-radius: 14px;
            padding: 1rem 1.15rem;
            margin-bottom: 1.25rem;
            font-size: .875rem;
            line-height: 1.55;
            animation: restIn .7s cubic-bezier(.22, 1, .36, 1) both;
        }

        @keyframes restIn {
            from {
                opacity: 0;
                transform: translateY(-12px) scale(.97);
            }

            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        .rest-banner-head {
            display: flex;
            align-items: center;
            gap: .55rem;
            font-family: var(--ff-h);
            font-size: .82rem;
            font-weight: 700;
            letter-spacing: .06em;
            text-transform: uppercase;
        }

        .rest-banner-icon {
            font-size: 1.1rem;
            flex-shrink: 0;
        }

        [data-period=morning] .rest-banner,
        [data-period=afternoon] .rest-banner {
            background: rgba(99, 102, 241, .10);
            border: 1px solid rgba(99, 102, 241, .28);
            color: #3730a3;
        }

        [data-period=evening] .rest-banner,
        [data-period=night] .rest-banner {
            background: rgba(99, 102, 241, .14);
            border: 1px solid rgba(129, 140, 248, .28);
            color: #c7d2fe;
        }

        [data-period=evening] .rest-banner-head,
        [data-period=night] .rest-banner-head {
            color: #a5b4fc;
        }

        .lock-note {
            text-align: center;
            font-size: .74rem;
            opacity: .52;
            margin-top: .55rem;
            letter-spacing: .02em;
        }

        /* ── FORM ── */
        .fg {
            margin-bottom: 1.15rem
        }

        label {
            display: block;
            font-size: .72rem;
            font-weight: 700;
            margin-bottom: .46rem;
            letter-spacing: .07em;
            text-transform: uppercase;
        }

        [data-period=morning] label,
        [data-period=afternoon] label {
            color: #374151
        }

        [data-period=evening] label,
        [data-period=night] label {
            color: #64748b
        }

        .iw {
            position: relative;
            display: flex;
            align-items: center
        }

        .iw .ic {
            position: absolute;
            left: 13px;
            width: 16px;
            height: 16px;
            opacity: .35;
            pointer-events: none;
            transition: opacity .2s;
            flex-shrink: 0;
        }

        .iw:focus-within .ic {
            opacity: .72
        }

        [data-period=morning] .iw .ic,
        [data-period=afternoon] .iw .ic {
            color: #374151
        }

        [data-period=evening] .iw .ic,
        [data-period=night] .iw .ic {
            color: #94a3b8
        }

        .iw input {
            width: 100%;
            padding: .90rem 3rem .90rem 2.78rem;
            border-radius: 13px;
            font-size: .95rem;
            font-family: var(--ff-b);
            outline: none;
            transition: border-color .28s, box-shadow .28s, background .28s;
            border: 1.5px solid transparent;
        }

        [data-period=morning] .iw input,
        [data-period=afternoon] .iw input {
            background: rgba(255, 255, 255, .92);
            border-color: rgba(0, 0, 0, .09);
            color: #111827;
        }

        [data-period=morning] .iw input:focus {
            border-color: #f97316;
            box-shadow: 0 0 0 3.5px rgba(249, 115, 22, .14);
            background: #fff
        }

        [data-period=afternoon] .iw input:focus {
            border-color: #0284c7;
            box-shadow: 0 0 0 3.5px rgba(2, 132, 199, .13);
            background: #fff
        }

        [data-period=evening] .iw input,
        [data-period=night] .iw input {
            background: rgba(255, 255, 255, .06);
            border-color: rgba(255, 255, 255, .11);
            color: #e2e8f0;
        }

        [data-period=evening] .iw input:focus {
            border-color: #a855f7;
            box-shadow: 0 0 0 3.5px rgba(168, 85, 247, .17);
            background: rgba(255, 255, 255, .09)
        }

        [data-period=night] .iw input:focus {
            border-color: #818cf8;
            box-shadow: 0 0 0 3.5px rgba(129, 140, 248, .17);
            background: rgba(255, 255, 255, .09)
        }

        [data-period=morning] .iw input::placeholder,
        [data-period=afternoon] .iw input::placeholder {
            color: rgba(107, 114, 128, .48)
        }

        [data-period=evening] .iw input::placeholder,
        [data-period=night] .iw input::placeholder {
            color: rgba(148, 163, 184, .42)
        }

        .eye {
            position: absolute;
            right: 12px;
            background: none;
            border: none;
            cursor: pointer;
            padding: 8px;
            min-width: 44px;
            min-height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: .48;
            transition: opacity .2s, transform .2s;
        }

        .eye:hover {
            opacity: .92;
            transform: scale(1.12)
        }

        .eye svg {
            width: 18px;
            height: 18px
        }

        [data-period=morning] .eye,
        [data-period=afternoon] .eye {
            color: #374151
        }

        [data-period=evening] .eye,
        [data-period=night] .eye {
            color: #94a3b8
        }

        /* ── SUBMIT ── */
        .btn-si {
            width: 100%;
            padding: 1rem;
            border: none;
            border-radius: 13px;
            font-family: var(--ff-h);
            font-size: .96rem;
            font-weight: 700;
            letter-spacing: .06em;
            text-transform: uppercase;
            cursor: pointer;
            color: #fff;
            margin-top: .6rem;
            position: relative;
            overflow: hidden;
            transition: transform .22s ease, box-shadow .22s, filter .18s;
        }

        [data-period=morning] .btn-si {
            background: linear-gradient(125deg, #9a3412, #c2410c, #ea580c, #f97316);
            box-shadow: 0 6px 26px rgba(194, 65, 12, .46), 0 2px 4px rgba(0, 0, 0, .12)
        }

        [data-period=afternoon] .btn-si {
            background: linear-gradient(125deg, #0c4a6e, #0369a1, #0284c7, #0ea5e9);
            box-shadow: 0 6px 26px rgba(3, 105, 161, .46), 0 2px 4px rgba(0, 0, 0, .12)
        }

        [data-period=evening] .btn-si {
            background: linear-gradient(125deg, #4c1d95, #6d28d9, #7c3aed, #a855f7);
            box-shadow: 0 6px 26px rgba(109, 40, 217, .52), 0 2px 4px rgba(0, 0, 0, .15)
        }

        [data-period=night] .btn-si {
            background: linear-gradient(125deg, #1e1b4b, #3730a3, #4f46e5, #818cf8);
            box-shadow: 0 6px 26px rgba(79, 70, 229, .52), 0 2px 4px rgba(0, 0, 0, .15)
        }

        .btn-si::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(105deg, transparent 30%, rgba(255, 255, 255, .25) 50%, transparent 70%);
            transform: translateX(-120%);
            transition: transform .6s ease;
        }

        .btn-si:hover::before {
            transform: translateX(120%)
        }

        .btn-si:hover {
            transform: translateY(-2.5px);
            filter: brightness(1.09)
        }

        .btn-si:active {
            transform: translateY(0);
            filter: brightness(.96)
        }

        .btn-si.loading {
            pointer-events: none;
            color: transparent
        }

        .btn-si.loading::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 22px;
            height: 22px;
            margin: -11px 0 0 -11px;
            border: 2.5px solid rgba(255, 255, 255, .28);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin .75s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg)
            }
        }

        /* ── FOOTER ── */
        .cfooter {
            text-align: center;
            margin-top: 1.6rem
        }

        .cfooter a {
            font-size: .84rem;
            font-weight: 500;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            opacity: .56;
            transition: gap .2s, opacity .2s;
        }

        .cfooter a:hover {
            gap: 10px;
            opacity: 1
        }

        [data-period=morning] .cfooter a {
            color: #c2410c
        }

        [data-period=afternoon] .cfooter a {
            color: #0369a1
        }

        [data-period=evening] .cfooter a {
            color: #c084fc
        }

        [data-period=night] .cfooter a {
            color: #818cf8
        }

        /* ── T&C VIEW BUTTON ── */
        .cfooter {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: .55rem;
        }

        .tc-view-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: var(--ff-b);
            font-size: .78rem;
            font-weight: 500;
            background: none;
            border: 1px solid transparent;
            border-radius: 8px;
            padding: 5px 11px;
            cursor: pointer;
            opacity: .52;
            transition: opacity .2s, border-color .2s, background .2s;
            letter-spacing: .01em;
        }

        .tc-view-btn:hover {
            opacity: 1;
        }

        [data-period=morning] .tc-view-btn {
            color: #c2410c;
            border-color: rgba(194, 65, 12, .22);
        }

        [data-period=morning] .tc-view-btn:hover {
            background: rgba(194, 65, 12, .07);
        }

        [data-period=afternoon] .tc-view-btn {
            color: #0369a1;
            border-color: rgba(3, 105, 161, .22);
        }

        [data-period=afternoon] .tc-view-btn:hover {
            background: rgba(3, 105, 161, .07);
        }

        [data-period=evening] .tc-view-btn {
            color: #c084fc;
            border-color: rgba(192, 132, 252, .22);
        }

        [data-period=evening] .tc-view-btn:hover {
            background: rgba(192, 132, 252, .07);
        }

        [data-period=night] .tc-view-btn {
            color: #818cf8;
            border-color: rgba(129, 140, 248, .22);
        }

        [data-period=night] .tc-view-btn:hover {
            background: rgba(129, 140, 248, .07);
        }

        /* ══════════════════════════════════════
   PAGE TRANSITION
══════════════════════════════════════ */
        /* Fade-in the whole page smoothly on every load/reload */
        @keyframes pageFadeIn {
            from {
                opacity: 0;
            }

            to {
                opacity: 1;
            }
        }

        html {
            animation: pageFadeIn .45s ease both;
        }

        /* Applied via JS just before a navigation so the page fades out cleanly */
        html.page-leaving {
            opacity: 0;
            transition: opacity .35s ease;
            pointer-events: none;
        }

        /* ── Tablet (481px – 768px) ── */
        @media (min-width: 481px) and (max-width: 768px) {
            #loginWrap {
                max-width: 420px;
            }
        }

        /* ── Large phone / small tablet (≤ 520px) ── */
        @media (max-width: 520px) {
            body {
                padding: 1rem;
                padding-top: max(1.25rem, env(safe-area-inset-top));
                padding-bottom: max(1.25rem, env(safe-area-inset-bottom));
                padding-left: max(1rem, env(safe-area-inset-left));
                padding-right: max(1rem, env(safe-area-inset-right));
                align-items: center;
                justify-content: center;
            }

            #loginWrap {
                max-width: 100%;
                width: 100%;
            }

            .card {
                border-radius: 22px;
            }

            .topbar {
                padding: 11px 16px;
                border-radius: 22px 22px 0 0;
            }

            .tbar-clock {
                font-size: .80rem;
            }

            .tbar-badge {
                font-size: .60rem;
                padding: 2px 8px;
            }

            .card-body {
                padding: 1.6rem 1.4rem 1.8rem;
            }

            .logo-img {
                width: 40px;
                height: 40px;
            }

            .brand-name {
                font-size: 1.18rem;
            }

            .brand-sub {
                font-size: .68rem;
            }

            .logo-zone {
                margin-bottom: 1.1rem;
            }

            .g-icon {
                font-size: 1.55rem;
            }

            .g-text {
                font-size: 1.38rem;
            }

            .sub-line {
                font-size: .84rem;
                margin-bottom: 1.2rem;
            }

            .iw input {
                padding: .88rem 3rem .88rem 2.65rem;
                font-size: .94rem;
            }

            .btn-si {
                padding: .95rem;
                font-size: .92rem;
                min-height: 52px;
            }

            .fg {
                margin-bottom: 1rem;
            }

            label {
                font-size: .70rem;
            }

            .rest-banner {
                padding: .85rem 1rem;
                font-size: .82rem;
            }

            .rest-banner-head {
                font-size: .76rem;
            }

            .cfooter {
                margin-top: 1.2rem;
            }

            .cfooter a {
                font-size: .86rem;
                padding: 8px 0;
                min-height: 44px;
            }
        }

        /* ── Small phone (≤ 430px) ── */
        @media (max-width: 430px) {
            body {
                padding: .85rem;
                padding-top: max(1rem, env(safe-area-inset-top));
                padding-bottom: max(1rem, env(safe-area-inset-bottom));
            }

            .card {
                border-radius: 20px;
            }

            .topbar {
                padding: 10px 14px;
                border-radius: 20px 20px 0 0;
            }

            .card-body {
                padding: 1.45rem 1.25rem 1.65rem;
            }

            .hdivider {
                margin: 0 -1.25rem 1.3rem;
            }

            .g-text {
                font-size: 1.28rem;
            }

            .brand-name {
                font-size: 1.08rem;
            }

            .iw input {
                padding: .84rem 2.9rem .84rem 2.6rem;
                font-size: .91rem;
            }
        }

        /* ── Small phone (≤ 390px) ── */
        @media (max-width: 390px) {
            body {
                padding: .75rem;
                padding-top: max(.9rem, env(safe-area-inset-top));
                padding-bottom: max(.9rem, env(safe-area-inset-bottom));
            }

            .card {
                border-radius: 18px;
            }

            .card-body {
                padding: 1.35rem 1.1rem 1.5rem;
            }

            .topbar {
                padding: 10px 13px;
                border-radius: 18px 18px 0 0;
            }

            .tbar-clock {
                font-size: .75rem;
                letter-spacing: .02em;
            }

            .tbar-badge {
                display: none;
            }

            .g-text {
                font-size: 1.22rem;
            }

            .g-icon {
                font-size: 1.3rem;
            }

            .brand-name {
                font-size: 1rem;
            }

            .logo-zone {
                margin-bottom: .9rem;
            }

            .logo-img {
                width: 36px;
                height: 36px;
            }

            .iw input {
                padding: .80rem 2.8rem .80rem 2.5rem;
                font-size: .89rem;
                border-radius: 11px;
            }

            .btn-si {
                padding: .88rem;
                font-size: .87rem;
                border-radius: 11px;
                min-height: 50px;
            }

            .hdivider {
                margin: 0 -1.1rem 1.2rem;
            }

            .rest-banner {
                border-radius: 11px;
                padding: .75rem .9rem;
                font-size: .78rem;
            }

            .admin-override-btn {
                font-size: .75rem;
                padding: .55rem .9rem;
            }
        }

        /* ── Tiny / legacy phones (≤ 320px) ── */
        @media (max-width: 320px) {
            body {
                padding: .6rem;
            }

            .card-body {
                padding: 1.1rem .9rem 1.25rem;
            }

            .hdivider {
                margin: 0 -.9rem 1.1rem;
            }

            .g-text {
                font-size: 1.08rem;
            }

            .sub-line {
                font-size: .76rem;
                margin-bottom: 1rem;
            }

            .iw input {
                font-size: .84rem;
                padding: .78rem 2.7rem .78rem 2.4rem;
            }

            .btn-si {
                padding: .82rem;
                font-size: .82rem;
            }

            .brand-name {
                font-size: .92rem;
            }

            .tbar-badge {
                display: none;
            }

            .logo-img {
                width: 30px;
                height: 30px;
            }
        }

        /* ── Landscape on short-height devices ── */
        @media (max-height: 620px) and (orientation: landscape) {
            body {
                align-items: flex-start;
                padding: .6rem 1.25rem;
                padding-top: max(.6rem, env(safe-area-inset-top));
                padding-bottom: max(.6rem, env(safe-area-inset-bottom));
                padding-left: max(1.25rem, env(safe-area-inset-left));
                padding-right: max(1.25rem, env(safe-area-inset-right));
            }

            #loginWrap {
                margin-top: auto;
                margin-bottom: auto;
                padding: .4rem 0;
            }

            .logo-zone {
                flex-direction: row;
                align-items: center;
                justify-content: flex-start;
                gap: .75rem;
                margin-bottom: .6rem;
                text-align: left;
            }

            .logo-zone .logo-wrap {
                flex-shrink: 0;
                justify-content: flex-start;
            }

            .logo-img {
                width: 34px;
                height: 34px;
            }

            .card-body {
                padding: 1rem 1.6rem 1.2rem;
            }

            .greeting {
                margin-bottom: .2rem;
            }

            .g-text {
                font-size: 1.18rem;
            }

            .g-icon {
                font-size: 1.3rem;
            }

            .sub-line {
                margin-bottom: .75rem;
                font-size: .80rem;
            }

            .hdivider {
                margin-bottom: .9rem;
            }

            .fg {
                margin-bottom: .75rem;
            }

            .btn-si {
                padding: .78rem;
                margin-top: .3rem;
            }

            .cfooter {
                margin-top: .9rem;
            }
        }

        /* ── Very short landscape (≤ 480px height) ── */
        @media (max-height: 480px) and (orientation: landscape) {
            .logo-zone {
                margin-bottom: .4rem;
            }

            .brand-sub {
                display: none;
            }

            .sub-line {
                margin-bottom: .55rem;
            }

            .hdivider {
                margin-bottom: .65rem;
            }

            .fg {
                margin-bottom: .6rem;
            }

            .cfooter {
                margin-top: .6rem;
            }
        }

        /* ══════════════════════════════════════
   2-STEP VERIFICATION / FINGERPRINT
══════════════════════════════════════ */
        .mfa-step {
            font-size: .84rem;
            line-height: 1.55;
            margin-bottom: .9rem;
            opacity: .80;
        }

        .mfa-box {
            border-radius: 12px;
            padding: .8rem 1rem;
            margin-bottom: 1rem;
            background: rgba(127, 127, 127, .12);
            border: 1px solid rgba(127, 127, 127, .28);
            text-align: center;
            word-break: break-all;
        }

        [data-period=morning] .mfa-box,
        [data-period=afternoon] .mfa-box {
            color: #1e293b;
        }

        [data-period=evening] .mfa-box,
        [data-period=night] .mfa-box {
            color: #e2e8f0;
        }

        .mfa-secret {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .98rem;
            font-weight: 600;
            letter-spacing: .12em;
            user-select: all;
        }

        .mfa-qr {
            display: flex;
            justify-content: center;
            margin-bottom: .9rem;
        }

        .mfa-qr:empty {
            display: none;
        }

        .mfa-qr img,
        .mfa-qr canvas {
            background: #fff;
            padding: 8px;
            border-radius: 10px;
        }

        .mfa-codes {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: .5rem .8rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .92rem;
            font-weight: 600;
            letter-spacing: .06em;
        }

        .iw input.otp-inp {
            text-align: center;
            letter-spacing: .38em;
            font-size: 1.2rem;
            font-weight: 600;
        }

        .mfa-form+.cfooter,
        .mfa-form+.mfa-form {
            margin-top: 1.2rem;
        }

        .btn-si:disabled {
            cursor: not-allowed;
        }
    </style>
</head>

<body>
    <canvas id="envCanvas"></canvas>
    <div id="vignette"></div>
    <div id="grain"></div>
    <div id="ffLayer"></div>

    <div id="loginWrap">
        <div class="card">

            <div class="topbar">
                <div class="tbar-l">
                    <span class="online-dot"></span>
                    <span id="tbEmoji">🌅</span>
                    <span class="tbar-clock" id="tbClock">12:00:00 PM</span>
                </div>
                <span class="tbar-badge" id="tbBadge">Morning</span>
            </div>

            <div class="card-body">
                <div class="logo-zone">
                    <div class="logo-wrap">
                        <img src="../unbound.png" alt="SM" class="logo-img" onerror="this.style.display='none'">
                    </div>
                    <div class="brand-name">Staff <em> Monitoring</em></div>
                    <div class="brand-sub">Department Portal</div>
                </div>

                <div class="greeting">
                    <span class="g-icon" id="gIcon">🌅</span>
                    <h1 class="g-text" id="gText">Good Morning!</h1>
                </div>
                <p class="sub-line"><?= mfa_e($subLine) ?></p>

                <div class="hdivider"></div>

                <?php if ($isRestHours): ?>
                    <div class="rest-banner" id="restBanner">

                        <span>Please rest. Portal access is temporarily unavailable during late-night hours.

                        </span>
                    </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="err">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="12" y1="8" x2="12" y2="12" />
                            <circle cx="12" cy="16" r=".5" fill="currentColor" />
                        </svg>
                        <span><?= htmlspecialchars($error) ?></span>
                    </div>
                <?php endif; ?>

                <?php if ($stage === 'login'): ?>
                <form method="POST" action="login.php" novalidate id="loginForm">
                    <input type="hidden" name="action" value="password">
                    <input type="hidden" name="csrf" value="<?= mfa_e(mfa_csrf_token()) ?>">
                    <div class="fg">
                        <label for="username">Username</label>
                        <div class="iw">
                            <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
                                <circle cx="12" cy="7" r="4" />
                            </svg>
                            <input type="text" id="username" name="username" placeholder="Enter your username" required autofocus autocomplete="username" autocapitalize="off" spellcheck="false">
                        </div>
                    </div>
                    <div class="fg">
                        <label for="password">Password</label>
                        <div class="iw">
                            <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" />
                                <path d="M7 11V7a5 5 0 0110 0v4" />
                            </svg>
                            <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
                            <button type="button" class="eye" id="eyeBtn">
                                <svg id="eyeSvg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>
                            </button>
                        </div>
                    </div>
                    <button type="submit" class="btn-si" id="submitBtn">Sign In &rarr;</button>

                </form>
                <?php if (mfa_webauthn_available()): ?>
                <style>
                    /* ── Fingerprint sign-in (theme-aware) ── */
                    #waLoginWrap{--wa-a:#c2410c;--wa-b:#fb923c;--wa-fg:#7c2d12;--wa-card:rgba(255,255,255,.82);--wa-line:rgba(194,65,12,.32)}
                    [data-period=afternoon] #waLoginWrap{--wa-a:#0369a1;--wa-b:#38bdf8;--wa-fg:#0c4a6e;--wa-line:rgba(3,105,161,.32)}
                    [data-period=evening] #waLoginWrap{--wa-a:#7c3aed;--wa-b:#c084fc;--wa-fg:#f5f3ff;--wa-card:rgba(255,255,255,.07);--wa-line:rgba(192,132,252,.40)}
                    [data-period=night] #waLoginWrap{--wa-a:#4f46e5;--wa-b:#818cf8;--wa-fg:#e0e7ff;--wa-card:rgba(255,255,255,.07);--wa-line:rgba(129,140,248,.40)}
                    .wa-or{display:flex;align-items:center;gap:10px;margin:18px 0 14px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.6}
                    .wa-or::before,.wa-or::after{content:"";flex:1;height:1px;background:currentColor;opacity:.35}
                    .wa-btn{position:relative;width:100%;display:flex;align-items:center;gap:14px;text-align:left;padding:12px 16px;border-radius:14px;border:1.5px solid var(--wa-line);background:var(--wa-card);color:var(--wa-fg);font-family:var(--ff-b);cursor:pointer;transition:transform .18s var(--ease),box-shadow .18s,border-color .18s,background .18s}
                    .wa-btn:hover:not(:disabled){transform:translateY(-2px);border-color:var(--wa-a);box-shadow:0 10px 26px rgba(0,0,0,.16)}
                    .wa-btn:active:not(:disabled){transform:translateY(0) scale(.99)}
                    .wa-btn:focus-visible{outline:3px solid var(--wa-b);outline-offset:2px}
                    .wa-btn:disabled{cursor:progress}
                    .wa-ic-wrap{position:relative;flex:0 0 46px;height:46px}
                    .wa-ic-wrap::before{content:"";position:absolute;inset:0;border-radius:50%;animation:waPulse 2.8s ease-out infinite}
                    @keyframes waPulse{0%{box-shadow:0 0 0 0 var(--wa-b);opacity:.55}70%{box-shadow:0 0 0 12px var(--wa-b);opacity:0}100%{opacity:0}}
                    .wa-ic{position:relative;overflow:hidden;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--wa-a),var(--wa-b));transition:background .3s}
                    .wa-ic svg{width:24px;height:24px;transition:transform .3s var(--ease)}
                    .wa-btn:hover:not(:disabled) .wa-ic svg{transform:scale(1.12)}
                    .wa-ic .i-ok{display:none}
                    .wa-btn.is-success .i-fp{display:none}
                    .wa-btn.is-success .i-ok{display:block}
                    .wa-btn.is-success .wa-ic{background:linear-gradient(135deg,#15803d,#4ade80)}
                    .wa-btn.is-success .wa-ic-wrap::before,.wa-btn.is-loading .wa-ic-wrap::before{animation:none}
                    .wa-scan{position:absolute;left:9px;right:9px;top:9px;height:2px;border-radius:2px;background:rgba(255,255,255,.95);box-shadow:0 0 8px #fff;opacity:0}
                    .wa-btn.is-loading .wa-scan{opacity:1;animation:waScan 1.1s ease-in-out infinite alternate}
                    @keyframes waScan{to{top:35px}}
                    .wa-tx b{display:block;font-family:var(--ff-h);font-size:.92rem;font-weight:700;letter-spacing:.01em}
                    .wa-tx small{display:block;font-size:.76rem;opacity:.78;margin-top:2px;line-height:1.35}
                    .wa-note{text-align:center;font-size:.76rem;line-height:1.45;opacity:.7;margin-top:.7rem}
                    .wa-note:empty{display:none}
                    .wa-ok{display:flex;align-items:center;gap:9px;border-radius:12px;padding:.8rem 1.1rem;margin-bottom:1rem;font-size:.875rem;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.30);color:#15803d;animation:stUp .4s var(--ease) both}
                    [data-period=evening] .wa-ok,[data-period=night] .wa-ok{color:#86efac}
                    @media (prefers-reduced-motion:reduce){.wa-ic-wrap::before,.wa-btn.is-loading .wa-scan{animation:none}.wa-btn{transition:none}}
                </style>
                <div id="waLoginWrap" style="display:none">
                    <div class="wa-or"><span>or</span></div>
                    <div class="err" id="waErr" role="alert" style="display:none">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="12" y1="8" x2="12" y2="12" />
                            <circle cx="12" cy="16" r=".5" fill="currentColor" />
                        </svg>
                        <span></span>
                    </div>
                    <div class="wa-ok" id="waOk" role="status" style="display:none">
                        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
                            <circle cx="12" cy="12" r="10" />
                            <polyline points="9 12 11.5 14.5 16 9" />
                        </svg>
                        <span></span>
                    </div>
                    <button type="button" class="wa-btn" id="waPasskeyBtn">
                        <span class="wa-ic-wrap"><span class="wa-ic">
                                <svg class="i-fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
                                    <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
                                    <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
                                    <path d="M2 12a10 10 0 0 1 18-6" />
                                    <path d="M2 16h.01" />
                                    <path d="M21.8 16c.2-2 .131-5.354 0-6" />
                                    <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
                                    <path d="M8.65 22c.21-.66.45-1.32.57-2" />
                                    <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
                                </svg>
                                <svg class="i-ok" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <polyline points="20 6 9 17 4 12" />
                                </svg>
                                <span class="wa-scan"></span>
                            </span></span>
                        <span class="wa-tx">
                            <b id="waTitle">Sign in with fingerprint</b>
                            <small id="waSub">Use your device's fingerprint, face or screen lock</small>
                        </span>
                    </button>
                    <p class="wa-note" id="waNote"></p>
                </div>
                <?php endif; ?>
                <?php elseif ($stage === 'verify'): ?>
                    <div class="err" id="clientErr" style="display:none">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="12" y1="8" x2="12" y2="12" />
                            <circle cx="12" cy="16" r=".5" fill="currentColor" />
                        </svg>
                        <span></span>
                    </div>
                    <form method="POST" action="login.php" novalidate id="mfaForm" class="mfa-form">
                        <input type="hidden" name="action" id="mfaAction" value="verify_totp">
                        <input type="hidden" name="csrf" value="<?= mfa_e(mfa_csrf_token()) ?>">
                        <div class="fg">
                            <label for="mfaCode" id="mfaLabel">Authentication code</label>
                            <div class="iw">
                                <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <polyline points="9 12 11 14 15 10" />
                                </svg>
                                <input type="text" id="mfaCode" name="code" class="otp-inp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="••••••" required autofocus>
                            </div>
                        </div>
                        <button type="submit" class="btn-si" id="mfaSubmit">Verify &rarr;</button>
                    </form>
                    <div class="cfooter">
                        <?php if ($hasBio): ?>
                            <button type="button" class="tc-view-btn" id="waLoginBtn">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M12 11c0 3.5-.5 6-2 8" />
                                    <path d="M8 15c.5-1.5 1-3 1-4a3 3 0 016 0c0 4-.5 7-2.5 10" />
                                    <path d="M5 12a7 7 0 0114 0c0 2 0 4-.5 6" />
                                    <path d="M3.5 17c.3-1.5.5-3 .5-5a8 8 0 0116 0" />
                                </svg>
                                Use fingerprint / biometrics
                            </button>
                        <?php endif; ?>
                        <button type="button" class="tc-view-btn" id="toggleBackup">Use a backup code instead</button>
                        <a href="login?cancel=1">&larr; Cancel</a>
                    </div>

                <?php elseif ($stage === 'enroll'): ?>
                    <p class="mfa-step"><strong>1.</strong> Install an authenticator app (Google Authenticator, Microsoft Authenticator or Authy), then scan this QR code.</p>
                    <div class="mfa-qr" id="qrBox" data-uri="<?= mfa_e($enrollUri) ?>"></div>
                    <p class="mfa-step">Can't scan? Type this key into the app:</p>
                    <div class="mfa-box mfa-secret"><?= mfa_e(trim(chunk_split($enrollSecret, 4, ' '))) ?></div>
                    <p class="mfa-step"><strong>2.</strong> Enter the 6-digit code the app shows.</p>
                    <form method="POST" action="login.php" novalidate class="mfa-form">
                        <input type="hidden" name="action" value="enroll_confirm">
                        <input type="hidden" name="csrf" value="<?= mfa_e(mfa_csrf_token()) ?>">
                        <div class="fg">
                            <label for="mfaCode">Authentication code</label>
                            <div class="iw">
                                <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <polyline points="9 12 11 14 15 10" />
                                </svg>
                                <input type="text" id="mfaCode" name="code" class="otp-inp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="••••••" required autofocus>
                            </div>
                        </div>
                        <button type="submit" class="btn-si">Activate &rarr;</button>
                    </form>
                    <div class="cfooter">
                        <a href="login?cancel=1">&larr; Cancel</a>
                    </div>

                <?php elseif ($stage === 'codes'): ?>
                    <p class="mfa-step">Save these one-time <strong>backup codes</strong> somewhere safe. Each works once if you lose your phone. They will <strong>not be shown again</strong>.</p>
                    <div class="mfa-box">
                        <div class="mfa-codes" id="codesGrid">
                            <?php foreach ($backupCodes as $bc): ?><span><?= mfa_e($bc) ?></span><?php endforeach; ?>
                        </div>
                    </div>
                    <div class="cfooter" style="margin:0 0 1rem">
                        <button type="button" class="tc-view-btn" id="copyCodes">Copy codes</button>
                    </div>
                    <form method="POST" action="login.php" class="mfa-form">
                        <input type="hidden" name="action" value="codes_ack">
                        <input type="hidden" name="csrf" value="<?= mfa_e(mfa_csrf_token()) ?>">
                        <button type="submit" class="btn-si">I've saved my codes &rarr;</button>
                    </form>

                <?php elseif ($stage === 'bio_offer'): ?>
                    <div class="err" id="clientErr" style="display:none">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="12" y1="8" x2="12" y2="12" />
                            <circle cx="12" cy="16" r=".5" fill="currentColor" />
                        </svg>
                        <span></span>
                    </div>
                    <p class="mfa-step">Register this device's <strong>fingerprint / Face ID / Windows Hello</strong>. Next time you can sign in with just a touch &mdash; no username, password or code needed. Your fingerprint never leaves your device.</p>
                    <button type="button" class="btn-si" id="waRegBtn">Register fingerprint on this device</button>
                    <form method="POST" action="login.php" class="mfa-form" id="bioContinue">
                        <input type="hidden" name="action" value="bio_continue">
                        <input type="hidden" name="skip" id="bioSkip" value="1">
                        <input type="hidden" name="csrf" value="<?= mfa_e(mfa_csrf_token()) ?>">
                        <div class="cfooter">
                            <button type="submit" class="tc-view-btn">Skip for now</button>
                        </div>
                    </form>
                <?php endif; ?>

                <?php if ($stage === 'login'): ?>
                <div class="cfooter">
                    <a href="../index">&larr; Back to Home</a>
                    <button type="button" class="tc-view-btn" id="tcViewBtn">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="16" y1="13" x2="8" y2="13" />
                            <line x1="16" y1="17" x2="8" y2="17" />
                        </svg>
                        View Terms &amp; Conditions
                    </button>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php if (is_file(__DIR__ . '/../chatbot_widget.php')) { require_once __DIR__ . '/../chatbot_widget.php'; } ?>


    <!-- ══════════════════════════════════════════════════
         TERMS & CONDITIONS MODAL — Enhanced UI/UX
    ══════════════════════════════════════════════════ -->
    <style>
        /* ══ BACKDROP ══════════════════════════════════════════════ */
        #tcBackdrop {
            position: fixed;
            inset: 0;
            z-index: 900;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            background: rgba(4, 7, 24, 0.78);
            backdrop-filter: blur(14px) saturate(1.5);
            -webkit-backdrop-filter: blur(14px) saturate(1.5);
            opacity: 0;
            visibility: hidden;
            transition: opacity .38s var(--ease), visibility .38s;
        }

        #tcBackdrop.open {
            opacity: 1;
            visibility: visible;
        }

        /* ══ MODAL SHELL ════════════════════════════════════════════ */
        #tcModal {
            position: relative;
            width: 100%;
            max-width: 700px;
            max-height: 92dvh;
            display: flex;
            flex-direction: column;
            border-radius: 26px;
            overflow: hidden;
            transform: translateY(52px) scale(.94);
            transition: transform .42s var(--ease);
            box-shadow:
                0 0 0 1px rgba(255, 255, 255, .11),
                0 2px 0 1px rgba(255, 255, 255, .16),
                0 20px 60px rgba(0, 0, 0, .50),
                0 60px 140px rgba(0, 0, 0, .40);
        }

        #tcBackdrop.open #tcModal {
            transform: translateY(0) scale(1);
        }

        /* ══ HEADER ════════════════════════════════════════════════ */
        #tcHeader {
            flex-shrink: 0;
            padding: 1.5rem 1.85rem 1.35rem;
            display: flex;
            align-items: flex-start;
            gap: 1.1rem;
            position: relative;
            overflow: hidden;
        }

        [data-period=morning] #tcHeader {
            background: linear-gradient(135deg, #7f1d00, #c2410c, #ea580c, #fb923c);
        }

        [data-period=afternoon] #tcHeader {
            background: linear-gradient(135deg, #0c4a6e, #0369a1, #0284c7, #38bdf8);
        }

        [data-period=evening] #tcHeader {
            background: linear-gradient(135deg, #1e1b4b, #3730a3, #7c3aed, #a855f7);
        }

        [data-period=night] #tcHeader {
            background: linear-gradient(135deg, #0f172a, #1e1b4b, #312e81, #4338ca);
        }

        /* shimmer */
        #tcHeader::after {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, transparent 0%, rgba(255, 255, 255, .13) 50%, transparent 100%);
            transform: translateX(-100%);
            animation: tcShimmer 4.2s ease-in-out infinite;
        }

        @keyframes tcShimmer {
            0% {
                transform: translateX(-100%);
            }

            60% {
                transform: translateX(130%);
            }

            100% {
                transform: translateX(130%);
            }
        }

        /* header icon pill */
        .tc-header-icon {
            width: 48px;
            height: 48px;
            border-radius: 14px;
            background: rgba(255, 255, 255, .18);
            border: 1.5px solid rgba(255, 255, 255, .30);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            position: relative;
            z-index: 1;
            box-shadow: 0 4px 14px rgba(0, 0, 0, .18);
        }

        .tc-header-icon svg {
            width: 24px;
            height: 24px;
            color: #fff;
        }

        .tc-header-text {
            position: relative;
            z-index: 1;
            flex: 1;
            min-width: 0;
        }

        .tc-header-text h2 {
            font-family: var(--ff-h);
            font-size: 1.18rem;
            font-weight: 800;
            color: #fff;
            letter-spacing: -.03em;
            line-height: 1.22;
            margin: 0 0 .28rem;
        }

        .tc-header-text p {
            font-family: var(--ff-b);
            font-size: .78rem;
            color: rgba(255, 255, 255, .72);
            margin: 0;
            line-height: 1.45;
        }

        /* org badge */
        .tc-org-badge {
            flex-shrink: 0;
            position: relative;
            z-index: 1;
            font-family: var(--ff-h);
            font-size: .60rem;
            font-weight: 700;
            letter-spacing: .12em;
            text-transform: uppercase;
            background: rgba(255, 255, 255, .16);
            border: 1px solid rgba(255, 255, 255, .28);
            border-radius: 99px;
            padding: 5px 13px;
            color: #fff;
            white-space: nowrap;
            align-self: flex-start;
        }

        /* version pill */
        #tcVersionPill {
            position: absolute;
            bottom: .9rem;
            right: 1.85rem;
            font-family: var(--ff-h);
            font-size: .58rem;
            font-weight: 600;
            letter-spacing: .08em;
            text-transform: uppercase;
            color: rgba(255, 255, 255, .50);
            z-index: 1;
        }

        /* ══ PROGRESS BAR ══════════════════════════════════════════ */
        #tcProgress {
            position: absolute;
            top: 0;
            left: 0;
            height: 3.5px;
            width: 0%;
            border-radius: 0 3px 3px 0;
            transition: width .18s linear;
            pointer-events: none;
            z-index: 20;
        }

        [data-period=morning] #tcProgress {
            background: linear-gradient(90deg, #ea580c, #fb923c);
        }

        [data-period=afternoon] #tcProgress {
            background: linear-gradient(90deg, #0284c7, #38bdf8);
        }

        [data-period=evening] #tcProgress {
            background: linear-gradient(90deg, #7c3aed, #a855f7);
        }

        [data-period=night] #tcProgress {
            background: linear-gradient(90deg, #4338ca, #818cf8);
        }

        /* ══ SCROLL HINT ═══════════════════════════════════════════ */
        #tcScrollHint {
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: .45rem;
            padding: .55rem 1rem;
            font-family: var(--ff-b);
            font-size: .74rem;
            font-weight: 500;
            letter-spacing: .01em;
            transition: opacity .35s, max-height .35s;
            max-height: 60px;
            overflow: hidden;
        }

        [data-period=morning] #tcScrollHint {
            background: rgba(234, 88, 12, .07);
            color: #c2410c;
        }

        [data-period=afternoon] #tcScrollHint {
            background: rgba(2, 132, 199, .07);
            color: #0369a1;
        }

        [data-period=evening] #tcScrollHint {
            background: rgba(168, 85, 247, .07);
            color: #a855f7;
        }

        [data-period=night] #tcScrollHint {
            background: rgba(129, 140, 248, .07);
            color: #818cf8;
        }

        #tcScrollHint.hidden {
            opacity: 0;
            max-height: 0;
            padding: 0;
            pointer-events: none;
        }

        .scroll-bounce {
            animation: scrollBounce 1.4s ease-in-out infinite;
        }

        @keyframes scrollBounce {

            0%,
            100% {
                transform: translateY(0);
            }

            50% {
                transform: translateY(4px);
            }
        }

        /* ══ SCROLLABLE BODY ═══════════════════════════════════════ */
        #tcBody {
            flex: 1 1 auto;
            overflow-y: auto;
            padding: 1.6rem 1.85rem;
            scroll-behavior: smooth;
        }

        [data-period=morning] #tcBody,
        [data-period=afternoon] #tcBody {
            background: rgba(255, 255, 255, .86);
            backdrop-filter: blur(40px) saturate(1.7);
            -webkit-backdrop-filter: blur(40px) saturate(1.7);
        }

        [data-period=evening] #tcBody,
        [data-period=night] #tcBody {
            background: rgba(5, 9, 28, .93);
            backdrop-filter: blur(40px) saturate(1.5);
            -webkit-backdrop-filter: blur(40px) saturate(1.5);
        }

        /* custom scrollbar */
        #tcBody::-webkit-scrollbar {
            width: 5px;
        }

        #tcBody::-webkit-scrollbar-track {
            background: transparent;
        }

        [data-period=morning] #tcBody::-webkit-scrollbar-thumb,
        [data-period=afternoon] #tcBody::-webkit-scrollbar-thumb {
            background: rgba(0, 0, 0, .16);
            border-radius: 4px;
        }

        [data-period=evening] #tcBody::-webkit-scrollbar-thumb,
        [data-period=night] #tcBody::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, .16);
            border-radius: 4px;
        }

        /* ══ CONTENT TYPOGRAPHY ════════════════════════════════════ */
        .tc-intro {
            font-family: var(--ff-b);
            font-size: .86rem;
            line-height: 1.70;
            margin-bottom: 1.4rem;
            padding: 1rem 1.1rem;
            border-radius: 14px;
            border-left: 3.5px solid transparent;
        }

        [data-period=morning] .tc-intro {
            background: rgba(234, 88, 12, .07);
            color: #374151;
            border-left-color: #ea580c;
        }

        [data-period=afternoon] .tc-intro {
            background: rgba(2, 132, 199, .07);
            color: #374151;
            border-left-color: #0284c7;
        }

        [data-period=evening] .tc-intro {
            background: rgba(168, 85, 247, .07);
            color: #cbd5e1;
            border-left-color: #a855f7;
        }

        [data-period=night] .tc-intro {
            background: rgba(129, 140, 248, .07);
            color: #cbd5e1;
            border-left-color: #818cf8;
        }

        .tc-section {
            margin-bottom: 1.25rem;
        }

        .tc-section-title {
            font-family: var(--ff-h);
            font-size: .80rem;
            font-weight: 700;
            letter-spacing: .06em;
            text-transform: uppercase;
            margin-bottom: .55rem;
            display: flex;
            align-items: center;
            gap: .55rem;
        }

        [data-period=morning] .tc-section-title {
            color: #c2410c;
        }

        [data-period=afternoon] .tc-section-title {
            color: #0369a1;
        }

        [data-period=evening] .tc-section-title {
            color: #a855f7;
        }

        [data-period=night] .tc-section-title {
            color: #818cf8;
        }

        .tc-section-num {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 22px;
            height: 22px;
            border-radius: 7px;
            font-size: .65rem;
            font-weight: 800;
            color: #fff;
            flex-shrink: 0;
        }

        [data-period=morning] .tc-section-num {
            background: #c2410c;
        }

        [data-period=afternoon] .tc-section-num {
            background: #0369a1;
        }

        [data-period=evening] .tc-section-num {
            background: #7c3aed;
        }

        [data-period=night] .tc-section-num {
            background: #4338ca;
        }

        .tc-section p {
            font-family: var(--ff-b);
            font-size: .84rem;
            line-height: 1.68;
            margin: 0 0 .55rem;
        }

        [data-period=morning] .tc-section p,
        [data-period=afternoon] .tc-section p {
            color: #374151;
        }

        [data-period=evening] .tc-section p,
        [data-period=night] .tc-section p {
            color: #94a3b8;
        }

        .tc-section ul {
            margin: .4rem 0 .6rem 1.15rem;
            padding: 0;
        }

        .tc-section ul li {
            font-family: var(--ff-b);
            font-size: .82rem;
            line-height: 1.65;
            margin-bottom: .3rem;
        }

        [data-period=morning] .tc-section ul li,
        [data-period=afternoon] .tc-section ul li {
            color: #4b5563;
        }

        [data-period=evening] .tc-section ul li,
        [data-period=night] .tc-section ul li {
            color: #94a3b8;
        }

        .tc-section strong {
            font-weight: 600;
        }

        [data-period=morning] .tc-section strong,
        [data-period=afternoon] .tc-section strong {
            color: #1f2937;
        }

        [data-period=evening] .tc-section strong,
        [data-period=night] .tc-section strong {
            color: #e2e8f0;
        }

        .tc-divider {
            border: none;
            height: 1px;
            margin: 1.1rem 0;
        }

        [data-period=morning] .tc-divider,
        [data-period=afternoon] .tc-divider {
            background: rgba(0, 0, 0, .07);
        }

        [data-period=evening] .tc-divider,
        [data-period=night] .tc-divider {
            background: rgba(255, 255, 255, .07);
        }

        /* DPO contact card */
        .tc-dpo-card {
            border-radius: 13px;
            padding: .9rem 1.1rem;
            margin-top: .55rem;
            display: flex;
            gap: .85rem;
            align-items: flex-start;
        }

        [data-period=morning] .tc-dpo-card {
            background: rgba(234, 88, 12, .07);
            border: 1px solid rgba(234, 88, 12, .17);
        }

        [data-period=afternoon] .tc-dpo-card {
            background: rgba(2, 132, 199, .07);
            border: 1px solid rgba(2, 132, 199, .17);
        }

        [data-period=evening] .tc-dpo-card {
            background: rgba(168, 85, 247, .07);
            border: 1px solid rgba(168, 85, 247, .17);
        }

        [data-period=night] .tc-dpo-card {
            background: rgba(129, 140, 248, .07);
            border: 1px solid rgba(129, 140, 248, .17);
        }

        .tc-dpo-card svg {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
            margin-top: 2px;
        }

        [data-period=morning] .tc-dpo-card svg {
            color: #c2410c;
        }

        [data-period=afternoon] .tc-dpo-card svg {
            color: #0369a1;
        }

        [data-period=evening] .tc-dpo-card svg {
            color: #a855f7;
        }

        [data-period=night] .tc-dpo-card svg {
            color: #818cf8;
        }

        .tc-dpo-card .dpo-info {
            font-family: var(--ff-b);
            font-size: .80rem;
            line-height: 1.60;
        }

        [data-period=morning] .tc-dpo-card .dpo-info,
        [data-period=afternoon] .tc-dpo-card .dpo-info {
            color: #374151;
        }

        [data-period=evening] .tc-dpo-card .dpo-info,
        [data-period=night] .tc-dpo-card .dpo-info {
            color: #94a3b8;
        }

        .tc-dpo-card .dpo-info strong {
            display: block;
            font-weight: 700;
            margin-bottom: .22rem;
        }

        [data-period=morning] .tc-dpo-card .dpo-info strong,
        [data-period=afternoon] .tc-dpo-card .dpo-info strong {
            color: #1f2937;
        }

        [data-period=evening] .tc-dpo-card .dpo-info strong,
        [data-period=night] .tc-dpo-card .dpo-info strong {
            color: #e2e8f0;
        }

        /* ══ FOOTER / ACTION AREA ══════════════════════════════════ */
        #tcFooter {
            flex-shrink: 0;
            padding: 1.15rem 1.85rem 1.4rem;
            display: flex;
            flex-direction: column;
            gap: .85rem;
        }

        [data-period=morning] #tcFooter {
            background: rgba(255, 255, 255, .92);
            border-top: 1px solid rgba(0, 0, 0, .07);
        }

        [data-period=afternoon] #tcFooter {
            background: rgba(255, 255, 255, .92);
            border-top: 1px solid rgba(0, 0, 0, .07);
        }

        [data-period=evening] #tcFooter {
            background: rgba(5, 9, 28, .95);
            border-top: 1px solid rgba(255, 255, 255, .07);
        }

        [data-period=night] #tcFooter {
            background: rgba(5, 9, 28, .95);
            border-top: 1px solid rgba(255, 255, 255, .07);
        }

        /* Checkbox row */
        .tc-checkbox-row {
            display: flex;
            align-items: flex-start;
            gap: .70rem;
            cursor: pointer;
            user-select: none;
            padding: .75rem .9rem;
            border-radius: 12px;
            transition: background .18s;
        }

        [data-period=morning] .tc-checkbox-row:hover {
            background: rgba(0, 0, 0, .04);
        }

        [data-period=afternoon] .tc-checkbox-row:hover {
            background: rgba(0, 0, 0, .04);
        }

        [data-period=evening] .tc-checkbox-row:hover {
            background: rgba(255, 255, 255, .04);
        }

        [data-period=night] .tc-checkbox-row:hover {
            background: rgba(255, 255, 255, .04);
        }

        /* custom checkbox */
        .tc-checkbox-wrap {
            flex-shrink: 0;
            width: 20px;
            height: 20px;
            border-radius: 6px;
            border: 2px solid transparent;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 1px;
            transition: background .18s, border-color .18s, box-shadow .18s;
        }

        [data-period=morning] .tc-checkbox-wrap {
            border-color: rgba(0, 0, 0, .22);
            background: rgba(255, 255, 255, .9);
        }

        [data-period=afternoon] .tc-checkbox-wrap {
            border-color: rgba(0, 0, 0, .22);
            background: rgba(255, 255, 255, .9);
        }

        [data-period=evening] .tc-checkbox-wrap {
            border-color: rgba(255, 255, 255, .22);
            background: rgba(255, 255, 255, .06);
        }

        [data-period=night] .tc-checkbox-wrap {
            border-color: rgba(255, 255, 255, .22);
            background: rgba(255, 255, 255, .06);
        }

        .tc-checkbox-wrap.checked {
            background: #4f46e5;
            border-color: #4f46e5;
            box-shadow: 0 0 0 3px rgba(79, 70, 229, .22);
        }

        [data-period=morning] .tc-checkbox-wrap.checked {
            background: #c2410c;
            border-color: #c2410c;
            box-shadow: 0 0 0 3px rgba(194, 65, 12, .18);
        }

        [data-period=afternoon] .tc-checkbox-wrap.checked {
            background: #0284c7;
            border-color: #0284c7;
            box-shadow: 0 0 0 3px rgba(2, 132, 199, .18);
        }

        [data-period=evening] .tc-checkbox-wrap.checked {
            background: #a855f7;
            border-color: #a855f7;
            box-shadow: 0 0 0 3px rgba(168, 85, 247, .22);
        }

        [data-period=night] .tc-checkbox-wrap.checked {
            background: #6366f1;
            border-color: #6366f1;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, .22);
        }

        .tc-checkbox-wrap svg {
            display: none;
            width: 12px;
            height: 12px;
            color: #fff;
            stroke-width: 3;
        }

        .tc-checkbox-wrap.checked svg {
            display: block;
        }

        .tc-checkbox-row input[type=checkbox] {
            display: none;
        }

        /* hidden; replaced by custom widget */

        .tc-checkbox-label {
            font-family: var(--ff-b);
            font-size: .83rem;
            line-height: 1.52;
            cursor: pointer;
        }

        [data-period=morning] .tc-checkbox-label {
            color: #374151;
        }

        [data-period=afternoon] .tc-checkbox-label {
            color: #374151;
        }

        [data-period=evening] .tc-checkbox-label {
            color: #94a3b8;
        }

        [data-period=night] .tc-checkbox-label {
            color: #94a3b8;
        }

        /* scroll-lock notice under checkbox */
        #tcScrollLock {
            display: flex;
            align-items: center;
            gap: .45rem;
            font-family: var(--ff-b);
            font-size: .74rem;
            padding: .5rem .9rem;
            border-radius: 9px;
            transition: opacity .3s;
        }

        [data-period=morning] #tcScrollLock {
            background: rgba(251, 146, 60, .10);
            color: #c2410c;
        }

        [data-period=afternoon] #tcScrollLock {
            background: rgba(56, 189, 248, .10);
            color: #0369a1;
        }

        [data-period=evening] #tcScrollLock {
            background: rgba(168, 85, 247, .10);
            color: #a855f7;
        }

        [data-period=night] #tcScrollLock {
            background: rgba(129, 140, 248, .10);
            color: #818cf8;
        }

        #tcScrollLock.hidden {
            display: none;
        }

        /* Action buttons */
        .tc-btn-row {
            display: flex;
            gap: .75rem;
        }

        .tc-btn-decline {
            flex: 1;
            padding: .875rem 1rem;
            border-radius: 13px;
            border: 1.5px solid transparent;
            background: transparent;
            font-family: var(--ff-h);
            font-size: .84rem;
            font-weight: 600;
            cursor: pointer;
            transition: background .18s, border-color .18s, transform .12s;
            letter-spacing: .01em;
        }

        [data-period=morning] .tc-btn-decline {
            color: #6b7280;
            border-color: rgba(0, 0, 0, .12);
        }

        [data-period=afternoon] .tc-btn-decline {
            color: #6b7280;
            border-color: rgba(0, 0, 0, .12);
        }

        [data-period=evening] .tc-btn-decline {
            color: #64748b;
            border-color: rgba(255, 255, 255, .11);
        }

        [data-period=night] .tc-btn-decline {
            color: #64748b;
            border-color: rgba(255, 255, 255, .11);
        }

        .tc-btn-decline:hover {
            background: rgba(0, 0, 0, .05);
            transform: scale(.98);
        }

        .tc-btn-agree {
            flex: 2.2;
            padding: .875rem 1.25rem;
            border-radius: 13px;
            border: none;
            font-family: var(--ff-h);
            font-size: .88rem;
            font-weight: 700;
            color: #fff;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            transition: transform .14s, box-shadow .14s, opacity .22s, filter .18s;
            letter-spacing: .03em;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: .5rem;
        }

        [data-period=morning] .tc-btn-agree {
            background: linear-gradient(135deg, #9a3412, #c2410c, #ea580c);
            box-shadow: 0 5px 22px rgba(194, 65, 12, .38);
        }

        [data-period=afternoon] .tc-btn-agree {
            background: linear-gradient(135deg, #0c4a6e, #0369a1, #0284c7);
            box-shadow: 0 5px 22px rgba(3, 105, 161, .38);
        }

        [data-period=evening] .tc-btn-agree {
            background: linear-gradient(135deg, #4c1d95, #7c3aed, #a855f7);
            box-shadow: 0 5px 22px rgba(124, 58, 237, .42);
        }

        [data-period=night] .tc-btn-agree {
            background: linear-gradient(135deg, #1e1b4b, #4338ca, #6366f1);
            box-shadow: 0 5px 22px rgba(67, 56, 202, .42);
        }

        .tc-btn-agree::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(105deg, transparent 30%, rgba(255, 255, 255, .22) 50%, transparent 70%);
            transform: translateX(-120%);
            transition: transform .55s ease;
        }

        .tc-btn-agree:not(:disabled):hover::before {
            transform: translateX(120%);
        }

        .tc-btn-agree:not(:disabled):hover {
            transform: translateY(-1.5px) scale(1.01);
            filter: brightness(1.06);
        }

        .tc-btn-agree:not(:disabled):active {
            transform: scale(.98);
            filter: brightness(.96);
        }

        .tc-btn-agree:disabled {
            opacity: .38;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* spinner inside agree button */
        .tc-btn-agree.loading #tcAgreeLabel {
            opacity: .4;
        }

        .tc-btn-agree .tc-spinner {
            display: none;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, .28);
            border-top-color: #fff;
            border-radius: 50%;
            animation: tcSpin .65s linear infinite;
            flex-shrink: 0;
        }

        .tc-btn-agree.loading .tc-spinner {
            display: block;
        }

        @keyframes tcSpin {
            to {
                transform: rotate(360deg);
            }
        }

        /* ══ STATUS MESSAGES ═══════════════════════════════════════ */
        .tc-status-msg {
            display: none;
            align-items: center;
            justify-content: center;
            gap: .55rem;
            padding: .8rem 1.1rem;
            border-radius: 12px;
            font-family: var(--ff-b);
            font-size: .84rem;
            font-weight: 500;
            text-align: center;
            animation: tcMsgIn .35s var(--ease) both;
        }

        .tc-status-msg.visible {
            display: flex;
        }

        @keyframes tcMsgIn {
            from {
                opacity: 0;
                transform: translateY(8px) scale(.97);
            }

            to {
                opacity: 1;
                transform: none;
            }
        }

        /* Success */
        #tcSuccessMsg {
            background: rgba(34, 197, 94, .10);
            border: 1px solid rgba(34, 197, 94, .22);
        }

        [data-period=morning] #tcSuccessMsg,
        [data-period=afternoon] #tcSuccessMsg {
            color: #15803d;
        }

        [data-period=evening] #tcSuccessMsg,
        [data-period=night] #tcSuccessMsg {
            color: #4ade80;
        }

        /* Declined */
        #tcDeclinedMsg {
            background: rgba(239, 68, 68, .10);
            border: 1px solid rgba(239, 68, 68, .22);
        }

        [data-period=morning] #tcDeclinedMsg,
        [data-period=afternoon] #tcDeclinedMsg {
            color: #dc2626;
        }

        [data-period=evening] #tcDeclinedMsg,
        [data-period=night] #tcDeclinedMsg {
            color: #f87171;
        }

        /* ══ RESPONSIVENESS ════════════════════════════════════════ */
        @media (max-width:600px) {
            #tcModal {
                border-radius: 20px;
                max-height: 96dvh;
            }

            #tcHeader {
                padding: 1.15rem 1.25rem 1.05rem;
                gap: .8rem;
            }

            .tc-header-text h2 {
                font-size: 1.02rem;
            }

            .tc-org-badge {
                display: none;
            }

            #tcBody {
                padding: 1.15rem 1.25rem;
            }

            #tcFooter {
                padding: .95rem 1.25rem 1.15rem;
                gap: .7rem;
            }

            .tc-btn-row {
                flex-direction: column;
            }

            .tc-btn-decline,
            .tc-btn-agree {
                flex: none;
                width: 100%;
            }
        }

        @media (max-height:560px) and (orientation:landscape) {
            #tcModal {
                max-height: 98dvh;
            }

            #tcHeader {
                padding: .85rem 1.5rem .80rem;
            }

            #tcBody {
                padding: .95rem 1.5rem;
            }

            #tcFooter {
                padding: .75rem 1.5rem .9rem;
            }
        }
    </style>

    <!-- ══ MODAL HTML ════════════════════════════════════════════ -->
    <div id="tcBackdrop" role="dialog" aria-modal="true" aria-labelledby="tcModalTitle">
        <div id="tcModal">
            <!-- progress bar at the very top of the modal -->
            <div id="tcProgress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div>

            <!-- Header -->
            <div id="tcHeader">
                <div class="tc-header-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <polyline points="10 9 9 9 8 9" />
                    </svg>
                </div>
                <div class="tc-header-text">
                    <h2 id="tcModalTitle">Terms &amp; Conditions / Data Privacy Notice</h2>
                    <p>Please read the full notice below before accessing the system.</p>
                </div>
                <span class="tc-org-badge">SCOPe</span>
                <span id="tcVersionPill">v<?= htmlspecialchars(isset($termsVersion) ? $termsVersion : '1.0') ?></span>
            </div>

            <!-- Scroll hint bar -->
            <div id="tcScrollHint" aria-live="polite">
                <svg class="scroll-bounce" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <polyline points="6 9 12 15 18 9" />
                </svg>
                <span>Scroll to the bottom to unlock the agreement checkbox</span>
            </div>

            <!-- Scrollable content -->
            <div id="tcBody">

                <div class="tc-intro">
                    This Data Privacy Notice is issued by <strong>Serve the Children and Older Persons Foundation, Inc. (SCOPe)</strong>
                    in compliance with the <strong>Data Privacy Act of 2012 (R.A. 10173)</strong>.
                    By using this system, you acknowledge that SCOPe collects and processes your personal data
                    in accordance with the terms outlined below.
                </div>

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">1</span>Introduction</div>
                    <p>Serve the Children and Older Persons Foundation, Inc., as a Personal Information Controller under the Data Privacy Act of 2012, is committed to protecting your personal data. We are responsible for determining the purposes and means of processing your personal information and ensuring that all data activities are conducted in a lawful, fair, and transparent manner.</p>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">2</span>Data Protection Officer</div>
                    <p>To oversee our compliance with data privacy laws and respond to inquiries or concerns related to personal data, we have designated a Data Protection Officer (DPO).</p>
                    <div class="tc-dpo-card">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
                            <circle cx="12" cy="7" r="4" />
                        </svg>
                        <div class="dpo-info">
                            <strong>Data Protection Officer — SCOPe</strong>
                            Email: dpo.servecop@gmail.com<br>
                            Phone: 09466034730<br>
                            Address: #1,3,5 Red Street Rainbow Village, San Isidro, Angono, Rizal
                        </div>
                    </div>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">3</span>Purpose of Data Processing</div>
                    <p>Your personal data is collected and processed primarily to support the effective implementation of Unbound SCOPe's programs. Specifically, it allows us to:</p>
                    <ul>
                        <li>Tailor our services to your needs and monitor your participation</li>
                        <li>Improve program delivery and fulfill documentation requirements</li>
                        <li>Comply with applicable legal and regulatory obligations</li>
                    </ul>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">4</span>Legal Basis for Processing</div>
                    <p>SCOPe processes personal data on the following legal grounds:</p>
                    <ul>
                        <li><strong>Consent</strong> — We rely on your voluntary, informed consent. For minors, the consent of a parent or legal guardian is required.</li>
                        <li><strong>Legitimate Interest</strong> — We process data to fulfill our legitimate interest in promoting developmental programs.</li>
                        <li><strong>Legal Obligation</strong> — We also process your data when required to comply with applicable laws, rules, and reporting mandates.</li>
                    </ul>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">5</span>Categories of Data Collected</div>
                    <p>Depending on the nature of the activity or service, we may collect:</p>
                    <ul>
                        <li>Personal information — full name, age, gender, date of birth</li>
                        <li>Contact information — address, phone number, or email</li>
                        <li>Educational background, career interests, or program-specific responses</li>
                        <li>Feedback or evaluation data</li>
                        <li>Parent or guardian details (when applicable)</li>
                        <li>Login metadata — IP address and device/browser information</li>
                    </ul>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">6</span>Method of Collection</div>
                    <p>We collect personal data through registration forms (physical or digital), verbal or written responses during sessions, feedback and evaluation tools, and observations and documentation made by facilitators or staff.</p>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">7</span>Data Recipients &amp; Sharing Policy</div>
                    <p>Only authorized individuals have access to your personal data — SCOPe staff, program coordinators, and trained facilitators bound by confidentiality obligations. Data may be shared with partner organizations under written agreements that ensure data protection standards. Your data will never be transferred outside the Philippines unless permitted by law and your express consent has been obtained.</p>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">8</span>Data Storage &amp; Retention</div>
                    <p>All collected data is securely stored. Digital records are protected using password-secured and encrypted systems; physical records are kept in locked cabinets with controlled access. Data is retained for a maximum of <strong>five (5) years</strong>, unless a longer period is legally required. After the retention period, data will be securely deleted or anonymized.</p>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">9</span>Data Protection Measures</div>
                    <ul>
                        <li>Role-based access controls and encryption</li>
                        <li>Staff orientation and confidentiality protocols</li>
                        <li>Secure storage facilities and system infrastructure</li>
                        <li>Regular assessments of privacy risks and data protection practices</li>
                    </ul>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">10</span>Your Rights as a Data Subject</div>
                    <p>Under the Data Privacy Act, you are entitled to the following rights:</p>
                    <ul>
                        <li><strong>Right to be Informed</strong> — Know why your data is being collected and how it will be used.</li>
                        <li><strong>Right to Access</strong> — Request a copy of the personal information we hold about you.</li>
                        <li><strong>Right to Object</strong> — Object to processing if you believe it is not in your best interest.</li>
                        <li><strong>Right to Rectification</strong> — Request corrections to inaccurate or outdated data.</li>
                        <li><strong>Right to Erasure or Blocking</strong> — Ask us to delete or block your data when no longer necessary.</li>
                        <li><strong>Right to Data Portability</strong> — Request your data in a transferable format.</li>
                        <li><strong>Right to File a Complaint</strong> — File a complaint with our DPO or the National Privacy Commission.</li>
                        <li><strong>Right to Damages</strong> — Claim compensation if you suffer damages due to a data privacy violation.</li>
                    </ul>
                </div>
                <hr class="tc-divider">

                <div class="tc-section">
                    <div class="tc-section-title"><span class="tc-section-num">11</span>Consent &amp; Effectivity</div>
                    <p>Before we collect your personal data, we will ask for your written, informed consent. For minors, this consent must come from a parent or legal guardian. Without this consent, we will not proceed with any data collection. This Privacy Notice is effective upon its release and will remain in effect until updated or amended. Any changes will be communicated to stakeholders through official channels.</p>
                </div>

            </div><!-- /tcBody -->

            <!-- Footer -->
            <div id="tcFooter">
                <!-- Scroll-lock notice (visible until user reaches the bottom) -->
                <div id="tcScrollLock">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
                        <rect x="3" y="11" width="18" height="11" rx="2" />
                        <path d="M7 11V7a5 5 0 0110 0v4" />
                    </svg>
                    Scroll through the full notice to enable the agreement checkbox.
                </div>

                <!-- Success / Declined messages -->
                <div id="tcSuccessMsg" class="tc-status-msg" role="status">
                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="9 12 11.5 14.5 16 9" />
                    </svg>
                    <span>You have agreed to the Terms &amp; Conditions. Redirecting…</span>
                </div>
                <div id="tcDeclinedMsg" class="tc-status-msg" role="alert">
                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="15" y1="9" x2="9" y2="15" />
                        <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    <span>You declined. Access is blocked until you accept the Terms.</span>
                </div>

                <!-- Custom checkbox -->
                <label class="tc-checkbox-row" for="tcCheckbox" id="tcCheckboxRow">
                    <input type="checkbox" id="tcCheckbox" disabled>
                    <span class="tc-checkbox-wrap" id="tcCheckboxWrap">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="20 6 9 17 4 12" />
                        </svg>
                    </span>
                    <span class="tc-checkbox-label">I have read, understood, and agree to the Data Privacy Notice and Terms &amp; Conditions of <strong>Serve the Children and Older Persons Foundation, Inc.</strong></span>
                </label>

                <!-- Buttons -->
                <div class="tc-btn-row" id="tcBtnRow">
                    <button class="tc-btn-decline" id="tcDeclineBtn" type="button">Decline &amp; Exit</button>
                    <button class="tc-btn-agree" id="tcAgreeBtn" type="button" disabled>
                        <span id="tcAgreeLabel">I Agree &amp; Continue</span>
                        <span class="tc-spinner"></span>
                    </button>
                </div>
            </div>

        </div><!-- /tcModal -->
    </div><!-- /tcBackdrop -->

    <script>
        /* Always show the page again (fixes blank page after Back/Forward or a failed submit) */
        window.addEventListener('pageshow', function() {
            document.documentElement.classList.remove('page-leaving');
            var b = document.querySelector('.btn-si.loading');
            if (b) { b.classList.remove('loading'); b.disabled = false; }
        });
    </script>
    <script>
        /* ══════════════════════════════════════════════════════════════
       TERMS & CONDITIONS MODAL LOGIC
    ══════════════════════════════════════════════════════════════ */
        (function() {
            var SHOW = <?= $showTermsModal ? 'true' : 'false' ?>;
            var TERMS_URL = <?= json_encode(
                                (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                                    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
                                    . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\') . '/terms_agreement.php'
                            ) ?>;
            var LOGIN_URL = <?= json_encode(
                                (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                                    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
                                    . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\') . '/login.php'
                            ) ?>;
            if (!SHOW) return;

            var backdrop = document.getElementById('tcBackdrop');
            var tcBody = document.getElementById('tcBody');
            var progress = document.getElementById('tcProgress');
            var scrollHint = document.getElementById('tcScrollHint');
            var scrollLock = document.getElementById('tcScrollLock');
            var checkbox = document.getElementById('tcCheckbox');
            var checkWrap = document.getElementById('tcCheckboxWrap');
            var checkRow = document.getElementById('tcCheckboxRow');
            var agreeBtn = document.getElementById('tcAgreeBtn');
            var agreeLabel = document.getElementById('tcAgreeLabel');
            var declineBtn = document.getElementById('tcDeclineBtn');
            var btnRow = document.getElementById('tcBtnRow');
            var successMsg = document.getElementById('tcSuccessMsg');
            var declinedMsg = document.getElementById('tcDeclinedMsg');
            var scrolledEnd = false;

            /* ── Open modal after page-entry animation ── */
            setTimeout(function() {
                backdrop.classList.add('open');
            }, 640);

            /* ── Custom checkbox sync ─────────────────── */
            function syncCheckbox() {
                if (checkbox.checked) {
                    checkWrap.classList.add('checked');
                } else {
                    checkWrap.classList.remove('checked');
                }
                agreeBtn.disabled = !checkbox.checked;
            }

            /* clicking the visible custom widget */
            checkWrap.addEventListener('click', function(e) {
                if (checkbox.disabled) return;
                e.stopPropagation();
                checkbox.checked = !checkbox.checked;
                syncCheckbox();
            });

            /* native checkbox change (keyboard, etc.) */
            checkbox.addEventListener('change', syncCheckbox);

            /* ── Scroll progress & unlock logic ──────── */
            function updateProgress() {
                var total = tcBody.scrollHeight - tcBody.clientHeight;
                var scrolled = tcBody.scrollTop;
                var pct = total > 0 ? Math.min(100, (scrolled / total) * 100) : 100;

                progress.style.width = pct + '%';
                progress.setAttribute('aria-valuenow', Math.round(pct));

                if (pct >= 92 && !scrolledEnd) {
                    scrolledEnd = true;
                    scrollHint.classList.add('hidden');
                    scrollLock.classList.add('hidden');
                    checkbox.disabled = false;
                    checkWrap.style.cursor = 'pointer';
                }

                /* Show scroll hint again when near top */
                if (scrolled < 12 && !scrolledEnd) {
                    scrollHint.classList.remove('hidden');
                }
            }

            checkbox.disabled = true;
            checkWrap.style.cursor = 'not-allowed';
            tcBody.addEventListener('scroll', updateProgress, {
                passive: true
            });
            setTimeout(updateProgress, 300); /* handle very short content */

            /* ── Shared: lock all buttons, prevent any double-fire ─── */
            var submitting = false;

            function lockUI(labelText) {
                submitting = true;
                agreeBtn.disabled = true;
                declineBtn.disabled = true;
                agreeBtn.classList.add('loading');
                agreeLabel.textContent = labelText || 'Processing…';
            }

            function unlockUI() {
                submitting = false;
                agreeBtn.disabled = false;
                declineBtn.disabled = false;
                agreeBtn.classList.remove('loading');
                agreeLabel.textContent = 'I Agree & Continue';
            }

            /* ── AGREE ───────────────────────────────── */
            agreeBtn.addEventListener('click', function() {
                if (submitting || agreeBtn.disabled) return;
                lockUI('Processing…');

                var xhr = new XMLHttpRequest();
                xhr.open('POST', TERMS_URL, true);
                xhr.timeout = 15000;

                xhr.onreadystatechange = function() {
                    if (xhr.readyState !== 4) return;

                    if (xhr.status === 200) {
                        var data;
                        try {
                            data = JSON.parse(xhr.responseText);
                        } catch (e) {
                            unlockUI();
                            alert('Server error — unexpected response:\n\n' + xhr.responseText.substring(0, 600));
                            return;
                        }

                        agreeBtn.classList.remove('loading');

                        if (data.success && data.action === 'agreed') {
                            checkRow.style.display = 'none';
                            btnRow.style.display = 'none';
                            scrollLock.classList.add('hidden');
                            successMsg.classList.add('visible');

                            setTimeout(function() {
                                document.documentElement.classList.add('page-leaving');
                                setTimeout(function() {
                                    window.location.href = data.redirect;
                                }, 360);
                            }, 1600);
                        } else {
                            unlockUI();
                            alert(data.message || 'An error occurred. Please try again.');
                        }
                    } else {
                        unlockUI();
                        alert('Server returned HTTP ' + xhr.status + '.\n\nURL: ' + TERMS_URL + '\n\nResponse:\n' + xhr.responseText.substring(0, 400));
                    }
                };

                xhr.ontimeout = function() {
                    unlockUI();
                    alert('Request timed out. Check your server is running.');
                };

                xhr.onerror = function() {
                    unlockUI();
                    alert('Could not reach:\n' + TERMS_URL + '\n\nMake sure terms_agreement.php is in your auth/ folder and your server is running.');
                };

                var fd = new FormData();
                fd.append('action', 'agree');
                xhr.send(fd);
            });

            /* ── DECLINE ─────────────────────────────── */
            declineBtn.addEventListener('click', function() {
                if (submitting) return;
                lockUI('Declining…');

                checkRow.style.display = 'none';
                btnRow.style.display = 'none';
                scrollLock.classList.add('hidden');
                declinedMsg.classList.add('visible');

                /* best-effort log to server */
                var xhr = new XMLHttpRequest();
                xhr.open('POST', TERMS_URL, true);
                xhr.timeout = 8000;
                var fd = new FormData();
                fd.append('action', 'decline');
                xhr.send(fd);

                /* always redirect regardless of server response */
                setTimeout(function() {
                    backdrop.classList.remove('open');
                    setTimeout(function() {
                        window.location.href = LOGIN_URL;
                    }, 400);
                }, 2400);
            });

            /* ── Keyboard: Escape = Decline ─────────── */
            backdrop.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') declineBtn.click();
            });

            /* ── Click outside modal = shake ─────────── */
            backdrop.addEventListener('click', function(e) {
                if (e.target !== backdrop) return;
                var modal = document.getElementById('tcModal');
                modal.style.animation = 'none';
                void modal.offsetHeight; /* reflow */
                modal.style.animation = 'tcShake .4s ease';
            });

            /* shake keyframe */
            var shakeStyle = document.createElement('style');
            shakeStyle.textContent = '@keyframes tcShake{0%,100%{transform:translateX(0);}20%{transform:translateX(-7px);}40%{transform:translateX(7px);}60%{transform:translateX(-4px);}80%{transform:translateX(4px);}}';
            document.head.appendChild(shakeStyle);

        })();
    </script>

    <script>
        /* ══════════════════════════════════════════════════════════════
       VIEW-ONLY T&C MODAL — triggered by the login page button
    ══════════════════════════════════════════════════════════════ */
        (function() {
            var viewBtn = document.getElementById('tcViewBtn');
            if (!viewBtn) return;

            var backdrop = document.getElementById('tcBackdrop');
            var footer = document.getElementById('tcFooter');
            var scrollHint = document.getElementById('tcScrollHint');
            var scrollLock = document.getElementById('tcScrollLock');
            var tcBody = document.getElementById('tcBody');
            var progress = document.getElementById('tcProgress');

            /* Build the close button once */
            var closeBtn = document.createElement('button');
            closeBtn.type = 'button';
            closeBtn.id = 'tcCloseBtn';
            closeBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Close';

            var s = closeBtn.style;
            s.width = '100%';
            s.padding = '.875rem 1.25rem';
            s.borderRadius = '13px';
            s.border = 'none';
            s.fontFamily = 'var(--ff-h)';
            s.fontSize = '.88rem';
            s.fontWeight = '700';
            s.letterSpacing = '.03em';
            s.color = '#fff';
            s.cursor = 'pointer';
            s.display = 'flex';
            s.alignItems = 'center';
            s.justifyContent = 'center';
            s.gap = '.5rem';
            s.transition = 'transform .14s, filter .18s';

            function applyCloseBtnColor() {
                var p = document.documentElement.dataset.period || 'night';
                var g = {
                    morning: 'linear-gradient(135deg,#9a3412,#c2410c,#ea580c)',
                    afternoon: 'linear-gradient(135deg,#0c4a6e,#0369a1,#0284c7)',
                    evening: 'linear-gradient(135deg,#4c1d95,#7c3aed,#a855f7)',
                    night: 'linear-gradient(135deg,#1e1b4b,#4338ca,#6366f1)'
                };
                closeBtn.style.background = g[p] || g.night;
                closeBtn.style.boxShadow = p === 'morning' ? '0 5px 22px rgba(194,65,12,.38)' :
                    p === 'afternoon' ? '0 5px 22px rgba(3,105,161,.38)' :
                    p === 'evening' ? '0 5px 22px rgba(124,58,237,.42)' :
                    '0 5px 22px rgba(67,56,202,.42)';
            }
            applyCloseBtnColor();

            closeBtn.addEventListener('mouseover', function() {
                closeBtn.style.filter = 'brightness(1.09)';
                closeBtn.style.transform = 'translateY(-1.5px)';
            });
            closeBtn.addEventListener('mouseout', function() {
                closeBtn.style.filter = '';
                closeBtn.style.transform = '';
            });

            /* Scroll progress bar in view mode */
            function updateViewProgress() {
                var total = tcBody.scrollHeight - tcBody.clientHeight;
                var scrolled = tcBody.scrollTop;
                var pct = total > 0 ? Math.min(100, (scrolled / total) * 100) : 100;
                progress.style.width = pct + '%';
                progress.setAttribute('aria-valuenow', Math.round(pct));
                if (scrolled < 12) scrollHint.classList.remove('hidden');
                else scrollHint.classList.add('hidden');
            }

            function openViewMode() {
                /* Reset state */
                tcBody.scrollTop = 0;
                progress.style.width = '0%';
                scrollHint.classList.remove('hidden');

                /* Replace footer with just the Close button */
                footer.innerHTML = '';
                footer.appendChild(closeBtn);
                applyCloseBtnColor();

                tcBody.addEventListener('scroll', updateViewProgress, {
                    passive: true
                });
                setTimeout(updateViewProgress, 100);

                backdrop.dataset.viewMode = '1';
                backdrop.classList.add('open');
            }

            function closeViewMode() {
                backdrop.classList.remove('open');
                delete backdrop.dataset.viewMode;
                tcBody.removeEventListener('scroll', updateViewProgress);
            }

            viewBtn.addEventListener('click', openViewMode);
            closeBtn.addEventListener('click', closeViewMode);

            /* Click outside = close in view mode */
            backdrop.addEventListener('click', function(e) {
                if (backdrop.dataset.viewMode && e.target === backdrop) closeViewMode();
            });

            /* Escape = close in view mode */
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && backdrop.dataset.viewMode) closeViewMode();
            });
        })();
    </script>

    <script>
        (function() {
            'use strict';
            /* ─── Helpers ─── */
            const $ = id => document.getElementById(id);
            const R = (a, b) => a + Math.random() * (b - a);
            const lerp = (a, b, t) => a + (b - a) * t;
            const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
            const PI2 = Math.PI * 2;
            const mobile = window.innerWidth < 600;

            /* ─── Period ─── */
            const period = h => h >= 5 && h < 12 ? 'morning' : h >= 12 && h < 17 ? 'afternoon' : h >= 17 && h < 21 ? 'evening' : 'night';
            const META = {
                morning: {
                    emoji: '🌅',
                    greet: 'Good Morning',
                    badge: 'Morning'
                },
                afternoon: {
                    emoji: '☀️',
                    greet: 'Good Afternoon',
                    badge: 'Afternoon'
                },
                evening: {
                    emoji: '🌆',
                    greet: 'Good Evening',
                    badge: 'Evening'
                },
                night: {
                    emoji: '🌙',
                    greet: 'Good Night',
                    badge: 'Night'
                },
            };

            /* ─── Clock ─── */
            let lastP = null;
            (function tick() {
                const n = new Date(),
                    h = n.getHours(),
                    m = n.getMinutes(),
                    s = n.getSeconds();
                const ap = h >= 12 ? 'PM' : 'AM',
                    hh = ((h % 12) || 12).toString().padStart(2, '0');
                $('tbClock').textContent = `${hh}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')} ${ap}`;
                const p = period(h),
                    meta = META[p];
                $('tbEmoji').textContent = meta.emoji;
                $('gIcon').textContent = meta.emoji;
                $('gText').textContent = meta.greet + '!';
                $('tbBadge').textContent = meta.badge;
                if (p !== lastP) {
                    document.documentElement.dataset.period = p;
                    lastP = p;
                }

                /* ── Dynamic rest-hours banner ── */
                const isRest = (h >= 23 || h < 5);
                const banner = $('restBanner');
                if (isRest && !banner) {
                    const b = document.createElement('div');
                    b.id = 'restBanner';
                    b.className = 'rest-banner';
                    b.innerHTML = `<div class="rest-banner-head"><span class="rest-banner-icon">🌙</span>System Rest Hours Active</div>` +
                        `<span>Please take some time to rest and recharge. Access to the portal is temporarily restricted during late-night hours for staff well-being and system maintenance.</span>`;
                    const hdiv = document.querySelector('.hdivider');
                    if (hdiv) hdiv.after(b);
                }
                if (!isRest && banner) banner.remove();

                setTimeout(tick, 1000);
            })();

            /* ─── Canvas ─── */
            const cv = $('envCanvas'),
                cx = cv.getContext('2d');
            let W, H;
            const rsz = () => {
                W = cv.width = window.innerWidth;
                H = cv.height = window.innerHeight;
            };
            rsz();
            window.addEventListener('resize', () => {
                rsz();
                initVC();
            }, {
                passive: true
            });

            /* ════════ SKY ════════ */
            const SKY = {
                morning: {
                    v: [
                        [0, '#f7a8b8'],
                        [.15, '#f9c9b6'],
                        [.30, '#f9c9b6'],
                        [.55, '#fad5b1'],
                        [.75, '#9cdbff'],
                        [1, '#e9f6ff']
                    ],
                    gx: .18,
                    gy: .72,
                    gc: 'rgba(249,168,184,.52)',
                    gr: .55,
                    g2x: .78,
                    g2c: 'rgba(250,213,177,.32)',
                    g2r: .44,
                },
                afternoon: {
                    v: [
                        [0, '#1e90ff'],
                        [.20, '#4facfe'],
                        [.35, '#4facfe'],
                        [.55, '#82c5ff'],
                        [.75, '#bce3ff'],
                        [1, '#f0f9ff']
                    ],
                    gx: .76,
                    gy: .04,
                    gc: 'rgba(79,172,254,.38)',
                    gr: .50,
                    g2x: .08,
                    g2c: 'rgba(188,227,255,.24)',
                    g2r: .40,
                },
                evening: {
                    v: [
                        [0, '#ff9a56'],
                        [.15, '#ff9a56'],
                        [.30, '#ff6b6b'],
                        [.55, '#c44d8b'],
                        [.75, '#5b2c6c'],
                        [1, '#1b1c3a']
                    ],
                    gx: .22,
                    gy: .30,
                    gc: 'rgba(255,107,107,.50)',
                    gr: .60,
                    g2x: .72,
                    g2c: 'rgba(196,77,139,.40)',
                    g2r: .50,
                },
                night: {
                    v: [
                        [0, '#0b0c1e'],
                        [.18, '#141852'],
                        [.40, '#141852'],
                        [.60, '#2c2f7a'],
                        [.80, '#1b3b6f'],
                        [1, '#0d1b2a']
                    ],
                    gx: .68,
                    gy: .12,
                    gc: 'rgba(44,47,122,.55)',
                    gr: .56,
                    g2x: .14,
                    g2c: 'rgba(27,59,111,.32)',
                    g2r: .42,
                },
            };

            function drawSky(p) {
                const s = SKY[p];
                const grd = cx.createLinearGradient(0, 0, 0, H);
                s.v.forEach(([t, c]) => grd.addColorStop(t, c));
                cx.fillStyle = grd;
                cx.fillRect(0, 0, W, H);
                const r1 = cx.createRadialGradient(s.gx * W, s.gy * H, 0, s.gx * W, s.gy * H, s.gr * W);
                r1.addColorStop(0, s.gc);
                r1.addColorStop(1, 'rgba(0,0,0,0)');
                cx.fillStyle = r1;
                cx.fillRect(0, 0, W, H);
                const r2 = cx.createRadialGradient(s.g2x * W, 0, 0, s.g2x * W, 0, s.g2r * W);
                r2.addColorStop(0, s.g2c);
                r2.addColorStop(1, 'rgba(0,0,0,0)');
                cx.fillStyle = r2;
                cx.fillRect(0, 0, W, H);
            }

            /* ════════ HORIZON FOG ════════ */
            function drawFog(p, t) {
                const fy = H * .70,
                    fh = H * .32;
                const wave = Math.sin(t * .0007) * .016;
                const cols = {
                    morning: [
                        [249, 180, 190],
                        [250, 210, 220]
                    ],
                    afternoon: [
                        [130, 197, 255],
                        [188, 227, 255]
                    ],
                    evening: [
                        [196, 77, 139],
                        [91, 44, 108]
                    ],
                    night: [
                        [20, 24, 82],
                        [11, 12, 30]
                    ],
                } [p] || [
                    [0, 0, 0],
                    [0, 0, 0]
                ];
                const g = cx.createLinearGradient(0, fy + wave * H, 0, fy + fh);
                g.addColorStop(0, `rgba(${cols[0]},0.26)`);
                g.addColorStop(.5, `rgba(${cols[1]},0.12)`);
                g.addColorStop(1, 'rgba(0,0,0,0)');
                cx.fillStyle = g;
                cx.fillRect(0, fy + wave * H, W, fh);
            }

            /* ════════ VOLUMETRIC CLOUDS ════════ */
            const VC = [];

            function initVC() {
                VC.length = 0;
                const n = mobile ? 6 : 12;
                for (let i = 0; i < n; i++) {
                    VC.push({
                        x: R(-.35, 1.35) * W,
                        y: R(.02, .50) * H,
                        w: R(160, 440),
                        h: R(50, 138),
                        spd: R(.07, .26) * (Math.random() > .5 ? 1 : -1),
                        alpha: R(.05, .20),
                        morph: R(0, PI2),
                        ms: R(.0007, .0028),
                        blobs: Array.from({
                            length: Math.floor(R(4, 10))
                        }, () => ({
                            ox: R(-.52, .52),
                            oy: R(-.42, .42),
                            r: R(.28, .72)
                        })),
                    });
                }
            }
            initVC();

            function drawVC(c, p, t) {
                const a = {
                    morning: .78,
                    afternoon: .80,
                    evening: .18,
                    night: .09
                } [p] || .80;
                const col = {
                    morning: [253, 235, 240],
                    afternoon: [230, 245, 255],
                    evening: [100, 40, 78],
                    night: [28, 40, 120]
                } [p] || [255, 255, 255];
                c.blobs.forEach(b => {
                    const bx = c.x + b.ox * c.w + Math.sin(c.morph + b.ox * 3) * c.w * .04;
                    const by = c.y + b.oy * c.h + Math.cos(c.morph + b.oy * 2) * c.h * .04;
                    const rx = c.w * b.r * .55,
                        ry = c.h * b.r * .65;
                    const g = cx.createRadialGradient(bx - rx * .2, by - ry * .2, 0, bx, by, Math.max(rx, ry));
                    g.addColorStop(0, `rgba(${col},${(c.alpha*a).toFixed(3)})`);
                    g.addColorStop(1, `rgba(${col},0)`);
                    cx.fillStyle = g;
                    cx.beginPath();
                    cx.ellipse(bx, by, rx, ry, 0, 0, PI2);
                    cx.fill();
                });
            }

            function updateVC(p, t) {
                VC.forEach(c => {
                    c.x += c.spd;
                    c.morph += c.ms;
                    if (c.spd > 0 && c.x > W + 480) {
                        c.x = -480;
                        c.y = R(.02, .50) * H;
                    }
                    if (c.spd < 0 && c.x < -480) {
                        c.x = W + 480;
                        c.y = R(.02, .50) * H;
                    }
                    drawVC(c, p, t);
                });
            }

            /* ════════ STARS ════════ */
            const STARS = Array.from({
                length: mobile ? 170 : 340
            }, () => ({
                x: R(0, 1),
                y: R(0, .78),
                r: R(.3, 2.0),
                ph: R(0, PI2),
                sp: R(.005, .024),
                col: Math.random() > .85 ? `hsl(${200+Math.random()*60|0},80%,95%)` : Math.random() > .7 ? `hsl(${25+Math.random()*35|0},65%,95%)` : '#fff',
            }));

            function drawStars(alpha, t) {
                STARS.forEach(s => {
                    const a = alpha * (0.48 + 0.52 * Math.sin(s.ph + t * s.sp));
                    if (a < .018) return;
                    cx.save();
                    cx.globalAlpha = a;
                    cx.fillStyle = s.col;
                    cx.shadowColor = s.col;
                    cx.shadowBlur = s.r * 4.5;
                    cx.beginPath();
                    cx.arc(s.x * W, s.y * H, s.r, 0, PI2);
                    cx.fill();
                    cx.restore();
                });
            }

            /* ════════ SHOOTING STARS ════════ */
            const shoots = [];
            let nextSh = R(10000, 22000),
                lastShT = 0;

            function spawnShoot() {
                const ang = R(20, 55) * Math.PI / 180,
                    sp = R(8, 18);
                shoots.push({
                    x: R(.08, .80) * W,
                    y: R(.02, .30) * H,
                    dx: Math.cos(ang) * sp,
                    dy: Math.sin(ang) * sp,
                    len: R(130, 270),
                    life: 0
                });
            }

            function updateShoots(t) {
                if (t - lastShT > nextSh) {
                    spawnShoot();
                    lastShT = t;
                    nextSh = R(10000, 22000);
                }
                for (let i = shoots.length - 1; i >= 0; i--) {
                    const s = shoots[i];
                    s.x += s.dx;
                    s.y += s.dy;
                    s.life += .030;
                    if (s.life >= 1) {
                        shoots.splice(i, 1);
                        continue;
                    }
                    const a = Math.sin(s.life * Math.PI);
                    const ratio = s.len / Math.sqrt(s.dx * s.dx + s.dy * s.dy);
                    const tx = s.x - s.dx * ratio,
                        ty = s.y - s.dy * ratio;
                    const g = cx.createLinearGradient(tx, ty, s.x, s.y);
                    g.addColorStop(0, 'rgba(220,235,255,0)');
                    g.addColorStop(1, `rgba(235,245,255,${(a*.94).toFixed(3)})`);
                    cx.save();
                    cx.globalAlpha = a;
                    cx.strokeStyle = g;
                    cx.lineWidth = 1.9;
                    cx.lineCap = 'round';
                    cx.beginPath();
                    cx.moveTo(tx, ty);
                    cx.lineTo(s.x, s.y);
                    cx.stroke();
                    cx.globalAlpha = a * .72;
                    cx.fillStyle = 'rgba(242,250,255,1)';
                    cx.shadowColor = 'rgba(200,225,255,1)';
                    cx.shadowBlur = 11;
                    cx.beginPath();
                    cx.arc(s.x, s.y, 2.5, 0, PI2);
                    cx.fill();
                    cx.restore();
                }
            }

            /* ════════ MOON ════════ */
            function drawMoon(mx, my, r, t) {
                /* large atmospheric halo */
                let h = cx.createRadialGradient(mx, my, r * .95, mx, my, r * 4.5);
                h.addColorStop(0, 'rgba(180,202,255,.30)');
                h.addColorStop(.45, 'rgba(140,170,255,.08)');
                h.addColorStop(1, 'rgba(0,0,0,0)');
                cx.save();
                cx.fillStyle = h;
                cx.beginPath();
                cx.arc(mx, my, r * 4.5, 0, PI2);
                cx.fill();
                cx.restore();
                /* subtle secondary ring */
                let h2 = cx.createRadialGradient(mx, my, r * 1.8, mx, my, r * 2.8);
                h2.addColorStop(0, 'rgba(170,195,255,.12)');
                h2.addColorStop(1, 'rgba(0,0,0,0)');
                cx.save();
                cx.fillStyle = h2;
                cx.beginPath();
                cx.arc(mx, my, r * 2.8, 0, PI2);
                cx.fill();
                cx.restore();
                /* disc */
                const g = cx.createRadialGradient(mx - r * .22, my - r * .22, 0, mx, my, r);
                g.addColorStop(0, '#f9fbfe');
                g.addColorStop(.44, '#e2e8f0');
                g.addColorStop(1, '#94a3b8');
                cx.save();
                cx.shadowColor = 'rgba(199,210,254,.75)';
                cx.shadowBlur = 38;
                cx.fillStyle = g;
                cx.beginPath();
                cx.arc(mx, my, r, 0, PI2);
                cx.fill();
                /* crescent */
                cx.globalCompositeOperation = 'destination-out';
                cx.beginPath();
                cx.arc(mx + r * .44, my - r * .06, r * .79, 0, PI2);
                cx.fill();
                cx.globalCompositeOperation = 'source-over';
                /* craters */
                [
                    [mx - r * .22, my + r * .30, r * .094],
                    [mx + r * .06, my - r * .22, r * .064],
                    [mx - r * .36, my - r * .04, r * .051],
                    [mx - .08 * r, my + r * .12, r * .040]
                ]
                .forEach(([x, y, cr]) => {
                    cx.globalAlpha = .12;
                    cx.fillStyle = '#475569';
                    cx.beginPath();
                    cx.arc(x, y, cr, 0, PI2);
                    cx.fill();
                });
                /* highlight sheen */
                cx.globalAlpha = .12 + Math.sin(t * .013) * .05;
                cx.fillStyle = 'rgba(255,255,255,.9)';
                cx.beginPath();
                cx.ellipse(mx - r * .27, my - r * .32, r * .24, r * .11, -.5, 0, PI2);
                cx.fill();
                cx.restore();
            }

            /* ════════ SUN ════════ */
            const SP = {
                morning: {
                    core: '#fff0f3',
                    mid: '#ffc8d0',
                    rim: '#f97fa0',
                    ray: 'rgba(249,127,160,.68)',
                    glow: 'rgba(250,180,190,.40)'
                },
                afternoon: {
                    core: '#ffffff',
                    mid: '#e8f4ff',
                    rim: '#4facfe',
                    ray: 'rgba(79,172,254,.58)',
                    glow: 'rgba(30,144,255,.26)'
                },
                evening: {
                    core: '#fff0e8',
                    mid: '#ff9a56',
                    rim: '#c44d8b',
                    ray: 'rgba(196,77,139,.68)',
                    glow: 'rgba(255,107,107,.42)'
                },
            };

            function drawSun(sx, sy, r, p, t) {
                const s = SP[p] || SP.afternoon;
                let g = cx.createRadialGradient(sx, sy, r * .4, sx, sy, r * 7);
                g.addColorStop(0, s.glow.replace(/[\d.]+\)$/, '.62)'));
                g.addColorStop(.28, s.glow);
                g.addColorStop(.72, s.glow.replace(/[\d.]+\)$/, '.08)'));
                g.addColorStop(1, 'rgba(0,0,0,0)');
                cx.save();
                cx.globalAlpha = .78;
                cx.fillStyle = g;
                cx.beginPath();
                cx.arc(sx, sy, r * 7, 0, PI2);
                cx.fill();
                cx.restore();
                /* god rays */
                const rc = 26;
                for (let i = 0; i < rc; i++) {
                    const ang = (i / rc) * PI2 + t * .0018;
                    const L1 = r + 5,
                        L2 = r + 42 + Math.sin(t * .036 + i * .9) * 14;
                    const a = (i % 2 === 0 ? .62 : .36) + Math.sin(t * .030 + i) * .18;
                    cx.save();
                    cx.globalAlpha = a;
                    cx.strokeStyle = s.ray;
                    cx.lineWidth = 1.8 + Math.sin(i * .7) * .9;
                    cx.lineCap = 'round';
                    cx.beginPath();
                    cx.moveTo(sx + Math.cos(ang) * L1, sy + Math.sin(ang) * L1);
                    cx.lineTo(sx + Math.cos(ang) * L2, sy + Math.sin(ang) * L2);
                    cx.stroke();
                    cx.restore();
                }
                /* disc */
                g = cx.createRadialGradient(sx - r * .20, sy - r * .20, 0, sx, sy, r);
                g.addColorStop(0, '#ffffff');
                g.addColorStop(.22, s.core);
                g.addColorStop(.62, s.mid);
                g.addColorStop(1, s.rim);
                cx.save();
                cx.shadowColor = s.rim;
                cx.shadowBlur = 50;
                cx.fillStyle = g;
                cx.beginPath();
                cx.arc(sx, sy, r, 0, PI2);
                cx.fill();
                cx.globalAlpha = .28 + Math.sin(t * .019) * .14;
                cx.fillStyle = '#fff';
                cx.shadowColor = '#fff';
                cx.shadowBlur = 22;
                cx.beginPath();
                cx.arc(sx - r * .28, sy - r * .28, r * .19, 0, PI2);
                cx.fill();
                cx.restore();
            }

            function sunXY(p, t) {
                const base = {
                    morning: .08,
                    afternoon: .50,
                    evening: .90
                } [p] || .50;
                const prog = clamp(base + Math.sin(t * .00022) * .009, 0, 1);
                return {
                    x: W * (.05 + prog * .90),
                    y: H * (.57 - Math.sin(prog * Math.PI) * .48)
                };
            }

            /* ════════ LENS FLARE ════════ */
            function drawFlare(sx, sy, r, t) {
                const fl = [{
                    d: .14,
                    s: r * .32,
                    a: .18
                }, {
                    d: .34,
                    s: r * .20,
                    a: .12
                }, {
                    d: .62,
                    s: r * .52,
                    a: .08
                }, {
                    d: .82,
                    s: r * .16,
                    a: .14
                }, {
                    d: 1.12,
                    s: r * .26,
                    a: .07
                }];
                const dx = W * .5 - sx,
                    dy = H * .5 - sy;
                fl.forEach(f => {
                    const fx = sx + dx * f.d,
                        fy = sy + dy * f.d;
                    const a = f.a * (0.68 + Math.sin(t * .022) * .32);
                    const g = cx.createRadialGradient(fx, fy, 0, fx, fy, f.s);
                    g.addColorStop(0, `rgba(255,245,195,${a.toFixed(3)})`);
                    g.addColorStop(1, 'rgba(0,0,0,0)');
                    cx.save();
                    cx.fillStyle = g;
                    cx.beginPath();
                    cx.arc(fx, fy, f.s, 0, PI2);
                    cx.fill();
                    cx.restore();
                });
            }

            /* ════════ AURORA BOREALIS (evening) ════════ */
            const AUR = Array.from({
                length: 9
            }, (_, i) => ({
                bx: i / 8,
                y: R(.18, .48),
                ph: R(0, PI2),
                sp: R(.0004, .0014)
            }));
            const ACOLS = [
                [
                    [120, 30, 180],
                    [80, 20, 140]
                ],
                [
                    [185, 30, 100],
                    [220, 55, 28]
                ],
                [
                    [28, 80, 185],
                    [20, 118, 162]
                ]
            ];

            function drawAurora(t) {
                for (let b = 0; b < 3; b++) {
                    const [c1, c2] = ACOLS[b % 3];
                    const pts = AUR.map(p => ({
                        x: p.bx * W,
                        y: (p.y + b * .065) * H + Math.sin(p.ph + t * p.sp + b) * H * .09
                    }));
                    cx.save();
                    cx.globalAlpha = .065 + b * .022;
                    const path = new Path2D();
                    path.moveTo(0, H);
                    pts.forEach((p, i) => {
                        if (!i) {
                            path.lineTo(p.x, p.y);
                        } else {
                            const pp = pts[i - 1];
                            path.bezierCurveTo(pp.x + (p.x - pp.x) * .4, pp.y, pp.x + (p.x - pp.x) * .6, p.y, p.x, p.y);
                        }
                    });
                    path.lineTo(W, H);
                    path.closePath();
                    const g = cx.createLinearGradient(0, H * .12, 0, H * .68);
                    g.addColorStop(0, `rgba(${c1},0)`);
                    g.addColorStop(.42, `rgba(${c1},.85)`);
                    g.addColorStop(1, `rgba(${c2},0)`);
                    cx.fillStyle = g;
                    cx.fill(path);
                    cx.restore();
                }
            }

            /* ════════ BIRDS ════════ */
            const BIRDS = Array.from({
                length: mobile ? 14 : 26
            }, () => ({
                x: R(0, 1) * window.innerWidth,
                y: R(18, window.innerHeight * .44),
                spd: R(.4, 1.55),
                flap: R(0, PI2),
                sz: R(2.4, 5.8),
                wav: R(.004, .014),
                woff: R(0, 100),
            }));

            function drawBird(x, y, sz, fl, a, dark) {
                cx.save();
                cx.globalAlpha = a;
                cx.strokeStyle = dark ? 'rgba(185,205,255,.56)' : 'rgba(8,18,48,.50)';
                cx.lineWidth = Math.max(.8, sz * .22);
                cx.lineCap = 'round';
                const w = Math.sin(fl) * sz * 1.28;
                cx.beginPath();
                cx.moveTo(x, y);
                cx.quadraticCurveTo(x - sz, y - w, x - sz * 2.1, y);
                cx.stroke();
                cx.beginPath();
                cx.moveTo(x, y);
                cx.quadraticCurveTo(x + sz, y - w, x + sz * 2.1, y);
                cx.stroke();
                cx.restore();
            }

            function updateBirds(a, p, t) {
                const dark = p === 'night' || p === 'evening';
                BIRDS.forEach(b => {
                    b.x += b.spd;
                    b.flap += .11;
                    b.y += Math.sin(t * b.wav + b.woff) * .30;
                    if (b.x > W + 110) {
                        b.x = -110;
                        b.y = R(18, H * .44);
                    }
                    drawBird(b.x, b.y, b.sz, b.flap, a, dark);
                });
            }

            /* ════════ OWLS ════════ */
            const OWLS = Array.from({
                length: 2
            }, () => ({
                x: R(-220, -60),
                y: R(H * .06, H * .38),
                spd: R(.20, .55),
                wing: R(0, PI2),
                sz: R(20, 32),
                wav: R(.003, .008),
                woff: R(0, 100),
            }));

            function drawOwl(x, y, sz, fl, a) {
                cx.save();
                cx.globalAlpha = a;
                const w = Math.sin(fl) * sz * .92;
                cx.fillStyle = 'rgba(14,9,32,.90)';
                /* wings */
                cx.save();
                cx.translate(x, y);
                cx.beginPath();
                cx.moveTo(0, sz * .06);
                cx.bezierCurveTo(-sz * .92, sz * .22, -sz * 1.12, -w * .5, -sz * .80, -sz * .28);
                cx.bezierCurveTo(-sz * .44, -sz * .12, 0, sz * .06, 0, sz * .06);
                cx.fill();
                cx.beginPath();
                cx.moveTo(0, sz * .06);
                cx.bezierCurveTo(sz * .92, sz * .22, sz * 1.12, -w * .5, sz * .80, -sz * .28);
                cx.bezierCurveTo(sz * .44, -sz * .12, 0, sz * .06, 0, sz * .06);
                cx.fill();
                cx.restore();
                /* body */
                cx.beginPath();
                cx.ellipse(x, y, sz * .28, sz * .40, 0, 0, PI2);
                cx.fill();
                /* head */
                cx.beginPath();
                cx.arc(x, y - sz * .34, sz * .22, 0, PI2);
                cx.fill();
                /* ear tufts */
                cx.strokeStyle = 'rgba(14,9,32,.90)';
                cx.lineWidth = 2.6;
                cx.lineCap = 'round';
                cx.beginPath();
                cx.moveTo(x - sz * .10, y - sz * .47);
                cx.lineTo(x - sz * .18, y - sz * .62);
                cx.stroke();
                cx.beginPath();
                cx.moveTo(x + sz * .10, y - sz * .47);
                cx.lineTo(x + sz * .18, y - sz * .62);
                cx.stroke();
                /* eyes glow */
                cx.fillStyle = 'rgba(255,210,50,.94)';
                cx.shadowColor = 'rgba(255,200,0,.65)';
                cx.shadowBlur = 7;
                cx.beginPath();
                cx.arc(x - sz * .088, y - sz * .34, sz * .060, 0, PI2);
                cx.fill();
                cx.beginPath();
                cx.arc(x + sz * .088, y - sz * .34, sz * .060, 0, PI2);
                cx.fill();
                cx.fillStyle = 'rgba(0,0,0,.96)';
                cx.shadowBlur = 0;
                cx.beginPath();
                cx.arc(x - sz * .088, y - sz * .34, sz * .031, 0, PI2);
                cx.fill();
                cx.beginPath();
                cx.arc(x + sz * .088, y - sz * .34, sz * .031, 0, PI2);
                cx.fill();
                /* beak */
                cx.fillStyle = 'rgba(175,125,38,.85)';
                cx.beginPath();
                cx.moveTo(x, y - sz * .28);
                cx.lineTo(x - sz * .032, y - sz * .22);
                cx.lineTo(x + sz * .032, y - sz * .22);
                cx.closePath();
                cx.fill();
                cx.restore();
            }

            function updateOwls(a, t) {
                OWLS.forEach(o => {
                    o.x += o.spd;
                    o.wing += .054;
                    o.y += Math.sin(t * o.wav + o.woff) * .27;
                    if (o.x > W + 160) {
                        o.x = -160;
                        o.y = R(H * .06, H * .38);
                    }
                    drawOwl(o.x, o.y, o.sz, o.wing, a);
                });
            }

            /* ════════ MIST PARTICLES ════════ */
            const MIST = Array.from({
                length: mobile ? 14 : 26
            }, () => ({
                x: R(0, 1),
                y: R(.30, 1.0),
                r: R(1.0, 4.5),
                vx: R(-.08, .08),
                vy: R(-.12, -.03),
                a: R(.04, .16),
                ph: R(0, PI2),
                sp: R(.011, .034),
            }));

            function drawMist(p, t) {
                if (p === 'night' || p === 'evening') return;
                const col = p === 'morning' ? [249, 168, 184] : [130, 197, 255];
                MIST.forEach(m => {
                    m.x += m.vx * .0009;
                    m.y += m.vy * .0009;
                    if (m.y < -.03) {
                        m.y = 1.03;
                        m.x = R(0, 1);
                    }
                    if (m.x < -.03 || m.x > 1.03) m.x = R(0, 1);
                    const a = m.a * (0.62 + 0.38 * Math.sin(m.ph + t * m.sp));
                    cx.save();
                    cx.globalAlpha = a;
                    cx.fillStyle = `rgba(${col},1)`;
                    cx.shadowColor = `rgba(${col},.65)`;
                    cx.shadowBlur = m.r * 3.5;
                    cx.beginPath();
                    cx.arc(m.x * W, m.y * H, m.r, 0, PI2);
                    cx.fill();
                    cx.restore();
                });
            }

            /* ════════ FIREFLIES ════════ */
            const ffLayer = $('ffLayer');
            const FF = mobile ? 14 : 28;
            const ffEls = [];
            let ffBuilt = false;
            const ffKf = document.createElement('style');
            document.head.appendChild(ffKf);

            function buildFF() {
                if (ffBuilt) return;
                ffBuilt = true;
                let kf = '';
                for (let i = 0; i < FF; i++) {
                    const sz = R(2.4, 5.6);
                    const r = 115 + Math.random() * 65 | 0,
                        g = 195 + Math.random() * 60 | 0,
                        b = 55 + Math.random() * 95 | 0;
                    const dx = R(-130, 130),
                        dy = R(-95, 95);
                    const dur = R(3, 8).toFixed(1),
                        del = R(0, 6).toFixed(1);
                    const oA = R(.14, .55).toFixed(2),
                        oB = R(.7, 1).toFixed(2);
                    kf += `@keyframes ff${i}{0%{transform:translate(0,0)scale(1);opacity:${oA};}50%{transform:translate(${dx/2}px,${dy/2}px)scale(1.35);opacity:${oB};}100%{transform:translate(${dx}px,${dy}px)scale(.75);opacity:${oA};}}`;
                    const el = document.createElement('div');
                    el.style.cssText = `position:absolute;width:${sz}px;height:${sz}px;border-radius:50%;` +
                        `left:${R(2,98)}%;top:${R(28,96)}%;` +
                        `background:rgba(${r},${g},${b},.94);` +
                        `box-shadow:0 0 ${sz*3.2}px ${sz*1.6}px rgba(${r},${g},${b},.32);` +
                        `animation:ff${i} ${dur}s ease-in-out ${del}s infinite alternate;` +
                        `opacity:0;transition:opacity 3s ease;pointer-events:none;`;
                    ffLayer.appendChild(el);
                    ffEls.push(el);
                }
                ffKf.textContent = kf;
            }

            function updateFF(p) {
                if (p === 'evening') {
                    buildFF();
                    ffEls.forEach(e => {
                        if (e.style.opacity !== '1') e.style.opacity = '1';
                    });
                } else {
                    ffEls.forEach(e => {
                        if (e.style.opacity !== '0') e.style.opacity = '0';
                    });
                }
            }

            /* ════════ MOUSE PARALLAX ════════ */
            let mx = 0,
                my = 0,
                pmx = 0,
                pmy = 0;
            const onMove = e => {
                const src = e.touches ? e.touches[0] : e;
                mx = (src.clientX / W - .5);
                my = (src.clientY / H - .5);
            };
            window.addEventListener('mousemove', onMove, {
                passive: true
            });
            window.addEventListener('touchmove', onMove, {
                passive: true
            });

            /* ════════ ALPHA BLEND TABLE ════════ */
            const TGT = {
                morning: {
                    stars: 0,
                    aurora: 0,
                    birds: .52,
                    owls: 0,
                    sun: 1,
                    moon: 0
                },
                afternoon: {
                    stars: 0,
                    aurora: 0,
                    birds: .42,
                    owls: 0,
                    sun: 1,
                    moon: 0
                },
                evening: {
                    stars: .42,
                    aurora: 1,
                    birds: .06,
                    owls: .70,
                    sun: 0,
                    moon: 0
                },
                night: {
                    stars: 1,
                    aurora: 0,
                    birds: .06,
                    owls: .80,
                    sun: 0,
                    moon: 1
                },
            };
            const CUR = {
                stars: 0,
                aurora: 0,
                birds: 0,
                owls: 0,
                sun: 0,
                moon: 0
            };

            function blendA(p, dt) {
                const tgt = TGT[p] || TGT.night,
                    s = .006 * dt;
                Object.keys(CUR).forEach(k => {
                    CUR[k] = lerp(CUR[k], tgt[k], s);
                });
            }

            /* ════════ MAIN LOOP ════════ */
            let tick = 0,
                last = 0;

            function render(ts) {
                const dt = Math.min(ts - last, 80);
                last = ts;
                tick++;
                cx.clearRect(0, 0, W, H);
                const p = period(new Date().getHours());
                blendA(p, dt);
                updateFF(p);

                drawSky(p);
                updateVC(p, tick);

                if (CUR.aurora > .01) {
                    cx.save();
                    cx.globalAlpha = CUR.aurora * .85;
                    drawAurora(tick);
                    cx.restore();
                }
                if (CUR.stars > .01) drawStars(CUR.stars, tick);
                if (p === 'night') updateShoots(tick);

                if (CUR.moon > .02) {
                    cx.save();
                    cx.globalAlpha = CUR.moon;
                    drawMoon(W * .76 + Math.sin(tick * .0014) * 10, H * .12 + Math.cos(tick * .0010) * 7, Math.min(W, H) * .062, tick);
                    cx.restore();
                }
                if (CUR.sun > .02) {
                    cx.save();
                    cx.globalAlpha = CUR.sun;
                    const pos = sunXY(p, tick),
                        r = Math.min(W, H) * .054;
                    drawSun(pos.x, pos.y, r, p, tick);
                    if (CUR.sun > .30) drawFlare(pos.x, pos.y, r, tick);
                    cx.restore();
                }
                if (CUR.birds > .01) updateBirds(CUR.birds, p, tick);
                if (CUR.owls > .01) updateOwls(CUR.owls, tick);

                drawMist(p, tick);
                drawFog(p, tick);

                /* parallax */
                pmx = lerp(pmx, mx, .055);
                pmy = lerp(pmy, my, .055);

                requestAnimationFrame(render);
            }
            requestAnimationFrame(render);

            /* ════════ CARD TILT ════════ */
            const card = document.querySelector('.card');
            if (card && !mobile) {
                document.addEventListener('mousemove', e => {
                    const rc = card.getBoundingClientRect();
                    const dx = (e.clientX - (rc.left + rc.width / 2)) / rc.width * 2;
                    const dy = (e.clientY - (rc.top + rc.height / 2)) / rc.height * 2;
                    card.style.transform = `perspective(900px) rotateY(${dx*3.8}deg) rotateX(${-dy*2.8}deg)`;
                }, {
                    passive: true
                });
                document.addEventListener('mouseleave', () => {
                    card.style.transform = 'perspective(900px) rotateY(0) rotateX(0)';
                });
            }

            /* ════════ FORM ════════ */
            const eyeBtn = $('eyeBtn'),
                pwdInp = $('password'),
                eyeSvg = $('eyeSvg');
            const EO = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
            const EC = `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>`;
            if (eyeBtn) eyeBtn.addEventListener('click', () => {
                const s = pwdInp.type === 'password';
                pwdInp.type = s ? 'text' : 'password';
                eyeSvg.innerHTML = s ? EC : EO;
            });

            const form = $('loginForm'),
                btn = $('submitBtn');
            if (form) form.addEventListener('submit', e => {
                const u = $('username').value.trim(),
                    pw = pwdInp.value;
                if (!u || !pw) {
                    e.preventDefault();
                    (!u ? $('username') : pwdInp).focus();
                    return;
                }
                btn.classList.add('loading');
                btn.disabled = true;
                // Smooth fade-out before the page navigates away
                document.documentElement.classList.add('page-leaving');
            });

            /* Smooth fade-out on "Back to Home" and any anchor navigation */
            document.querySelectorAll('a[href]').forEach(a => {
                a.addEventListener('click', function(e) {
                    const href = this.getAttribute('href');
                    if (!href || href.startsWith('#') || href.startsWith('javascript')) return;
                    e.preventDefault();
                    document.documentElement.classList.add('page-leaving');
                    setTimeout(() => {
                        window.location.href = href;
                    }, 360);
                });
            });

        })();
    </script>
    <?php if ($stage !== 'login'): ?>
        <?php if ($stage === 'enroll'): ?>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
        <?php endif; ?>
        <script>
            /* ══════════════════════════════════════════════════════════════
               2-STEP VERIFICATION + FINGERPRINT (WebAuthn) — client side
            ══════════════════════════════════════════════════════════════ */
            (function() {
                'use strict';
                var CSRF = <?= json_encode(mfa_csrf_token()) ?>;
                var $ = function(id) {
                    return document.getElementById(id);
                };

                function showErr(msg) {
                    var el = $('clientErr');
                    if (!el) return;
                    el.querySelector('span').textContent = msg;
                    el.style.display = 'flex';
                    el.style.animation = 'none';
                    void el.offsetHeight;
                    el.style.animation = '';
                }

                /* ── binary helpers (the server sends binary fields as "=?BINARY?B?<base64>?=") ── */
                function b64ToBuf(s) {
                    var bin = atob(s),
                        a = new Uint8Array(bin.length);
                    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
                    return a.buffer;
                }

                function bufToB64(buf) {
                    var b = new Uint8Array(buf),
                        s = '';
                    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
                    return btoa(s);
                }

                function decodeBin(o) {
                    if (Array.isArray(o)) return o.map(decodeBin);
                    if (o && typeof o === 'object') {
                        for (var k in o) o[k] = decodeBin(o[k]);
                        return o;
                    }
                    if (typeof o === 'string' && o.indexOf('=?BINARY?B?') === 0 && o.slice(-2) === '?=') {
                        return b64ToBuf(o.slice(11, -2));
                    }
                    return o;
                }

                function api(action, fields) {
                    var fd = new FormData();
                    fd.append('csrf', CSRF);
                    fd.append('action', action);
                    for (var k in (fields || {})) fd.append(k, fields[k]);
                    return fetch('login.php', {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    }).then(function(r) {
                        return r.json().catch(function() {
                            return {
                                success: false,
                                message: 'Unexpected server response.'
                            };
                        });
                    });
                }

                function leave(url) {
                    document.documentElement.classList.add('page-leaving');
                    setTimeout(function() {
                        window.location.href = url;
                    }, 360);
                }

                /* ── code input: backup-code toggle + input cleaning ── */
                var backupMode = false;
                var codeInp = $('mfaCode');
                var toggle = $('toggleBackup');
                if (codeInp) {
                    codeInp.addEventListener('input', function() {
                        codeInp.value = backupMode ?
                            codeInp.value.toUpperCase().replace(/[^A-Z0-9-]/g, '') :
                            codeInp.value.replace(/\D/g, '');
                    });
                }
                if (toggle && codeInp) {
                    toggle.addEventListener('click', function() {
                        backupMode = !backupMode;
                        $('mfaAction').value = backupMode ? 'verify_backup' : 'verify_totp';
                        $('mfaLabel').textContent = backupMode ? 'Backup code' : 'Authentication code';
                        codeInp.maxLength = backupMode ? 11 : 6;
                        codeInp.inputMode = backupMode ? 'text' : 'numeric';
                        codeInp.placeholder = backupMode ? 'XXXXX-XXXXX' : '••••••';
                        codeInp.value = '';
                        toggle.textContent = backupMode ? 'Use authenticator code instead' : 'Use a backup code instead';
                        codeInp.focus();
                    });
                }

                /* ── form submit: loading state + empty check ── */
                document.querySelectorAll('form.mfa-form').forEach(function(f) {
                    f.addEventListener('submit', function(e) {
                        var c = f.querySelector('input[name=code]');
                        if (c && !c.value.trim()) {
                            e.preventDefault();
                            c.focus();
                            return;
                        }
                        var b = f.querySelector('.btn-si');
                        if (b) {
                            b.classList.add('loading');
                            setTimeout(function() {
                                b.disabled = true;
                            }, 0);
                        }
                        document.documentElement.classList.add('page-leaving');
                    });
                });

                /* ── QR code (enrolment) ── */
                var qr = $('qrBox');
                if (qr && window.QRCode) {
                    new QRCode(qr, {
                        text: qr.getAttribute('data-uri'),
                        width: 176,
                        height: 176,
                        correctLevel: QRCode.CorrectLevel.M
                    });
                }

                /* ── copy backup codes ── */
                var cc = $('copyCodes');
                if (cc) {
                    cc.addEventListener('click', function() {
                        var t = Array.prototype.map.call(document.querySelectorAll('#codesGrid span'), function(s) {
                            return s.textContent;
                        }).join('\n');
                        var done = function() {
                            cc.textContent = 'Copied ✓';
                        };
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(t).then(done, function() {
                                cc.textContent = 'Select the codes and press Ctrl+C';
                            });
                        } else {
                            cc.textContent = 'Select the codes and press Ctrl+C';
                        }
                    });
                }

                /* ── FINGERPRINT SIGN-IN ── */
                var waLogin = $('waLoginBtn');
                if (waLogin) {
                    waLogin.addEventListener('click', function() {
                        if (!window.PublicKeyCredential || !navigator.credentials) {
                            showErr('Fingerprint sign-in is not supported on this browser/device (HTTPS is required).');
                            return;
                        }
                        waLogin.disabled = true;
                        api('wa_login_args').then(function(a) {
                            if (!a.success) {
                                if (a.redirect) {
                                    leave(a.redirect);
                                    return Promise.reject({
                                        handled: true
                                    });
                                }
                                return Promise.reject(new Error(a.message));
                            }
                            return navigator.credentials.get(decodeBin(a.args));
                        }).then(function(cred) {
                            return api('wa_login_verify', {
                                id: bufToB64(cred.rawId),
                                clientDataJSON: bufToB64(cred.response.clientDataJSON),
                                authenticatorData: bufToB64(cred.response.authenticatorData),
                                signature: bufToB64(cred.response.signature)
                            });
                        }).then(function(r) {
                            if (r.success) return leave(r.redirect);
                            if (r.redirect) return leave(r.redirect);
                            return Promise.reject(new Error(r.message));
                        }).catch(function(e) {
                            if (e && e.handled) return;
                            showErr(e && e.name === 'NotAllowedError' ?
                                'Fingerprint prompt was cancelled or timed out.' :
                                ((e && e.message) || 'Fingerprint verification failed.'));
                            waLogin.disabled = false;
                        });
                    });
                }

                /* ── FINGERPRINT REGISTRATION ── */
                var waReg = $('waRegBtn');
                if (waReg) {
                    waReg.addEventListener('click', function() {
                        if (!window.PublicKeyCredential || !navigator.credentials) {
                            showErr('This browser/device does not support fingerprint sign-in (HTTPS is required). You can skip this step.');
                            return;
                        }
                        waReg.disabled = true;
                        api('wa_reg_args').then(function(a) {
                            if (!a.success) {
                                if (a.redirect) {
                                    leave(a.redirect);
                                    return Promise.reject({
                                        handled: true
                                    });
                                }
                                return Promise.reject(new Error(a.message));
                            }
                            return navigator.credentials.create(decodeBin(a.args));
                        }).then(function(cred) {
                            return api('wa_reg_verify', {
                                clientDataJSON: bufToB64(cred.response.clientDataJSON),
                                attestationObject: bufToB64(cred.response.attestationObject)
                            });
                        }).then(function(r) {
                            if (!r.success) return Promise.reject(new Error(r.message));
                            document.documentElement.classList.add('page-leaving');
                            $('bioSkip').value = '0';
                            $('bioContinue').submit();
                        }).catch(function(e) {
                            if (e && e.handled) return;
                            showErr(e && e.name === 'NotAllowedError' ?
                                'Registration was cancelled or timed out.' :
                                ((e && e.message) || 'Could not register this device.'));
                            waReg.disabled = false;
                        });
                    });
                }
            })();
        </script>
    <?php endif; ?>
    <?php if ($stage === 'login' && mfa_webauthn_available()): ?>
        <script>
            /* ══════════ FINGERPRINT SIGN-IN FROM THE LOGIN SCREEN (WebAuthn passkey) ══════════ */
            (function() {
                'use strict';
                var $ = function(id) { return document.getElementById(id); };
                var wrap = $('waLoginWrap'),
                    btn = $('waPasskeyBtn');
                if (!wrap || !btn) return;
                var errBox = $('waErr'),
                    okBox = $('waOk'),
                    note = $('waNote'),
                    title = $('waTitle'),
                    sub = $('waSub');
                var CSRF = <?= json_encode(mfa_csrf_token()) ?>;
                var IDLE_TITLE = title.textContent,
                    IDLE_SUB = sub.textContent;
                var busy = false;

                /* Honest capability check — never claim fingerprint works where it cannot */
                var secure = window.isSecureContext === true;
                var supported = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
                wrap.style.display = 'block';
                if (!secure || !supported) {
                    btn.style.display = 'none';
                    var orLine = wrap.querySelector('.wa-or');
                    if (orLine) orLine.style.display = 'none';
                    note.textContent = !secure ?
                        'Fingerprint sign-in needs a secure (HTTPS) connection, so it is unavailable on this address.' :
                        'This browser or device does not support fingerprint (passkey) sign-in. Please use your username and password.';
                    return;
                }
                if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
                    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(function(ok) {
                        if (!ok) note.textContent = 'No built-in fingerprint or screen-lock sensor was detected on this device. A passkey saved on another device may still work.';
                    }).catch(function() {});
                }

                function show(box, msg) {
                    box.querySelector('span').textContent = msg;
                    box.style.display = 'flex';
                    box.style.animation = 'none';
                    void box.offsetHeight;
                    box.style.animation = '';
                }

                function hide(box) { box.style.display = 'none'; }

                function setState(s) {
                    busy = (s === 'loading' || s === 'success');
                    btn.classList.toggle('is-loading', s === 'loading');
                    btn.classList.toggle('is-success', s === 'success');
                    btn.disabled = busy;
                    btn.setAttribute('aria-busy', s === 'loading' ? 'true' : 'false');
                    if (s === 'loading') {
                        title.textContent = 'Waiting for your device\u2026';
                        sub.textContent = 'Touch your fingerprint sensor to continue.';
                    } else if (s === 'success') {
                        title.textContent = 'Verified';
                        sub.textContent = 'Signing you in\u2026';
                    } else {
                        title.textContent = IDLE_TITLE;
                        sub.textContent = IDLE_SUB;
                    }
                }

                /* The server sends binary fields as "=?BINARY?B?<base64>?=" */
                function b64ToBuf(s) {
                    var bin = atob(s),
                        a = new Uint8Array(bin.length);
                    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
                    return a.buffer;
                }

                function bufToB64(buf) {
                    var b = new Uint8Array(buf),
                        s = '';
                    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
                    return btoa(s);
                }

                function decodeBin(o) {
                    if (Array.isArray(o)) return o.map(decodeBin);
                    if (o && typeof o === 'object') {
                        for (var k in o) o[k] = decodeBin(o[k]);
                        return o;
                    }
                    if (typeof o === 'string' && o.indexOf('=?BINARY?B?') === 0 && o.slice(-2) === '?=') {
                        return b64ToBuf(o.slice(11, -2));
                    }
                    return o;
                }

                function api(action, fields) {
                    var fd = new FormData();
                    fd.append('csrf', CSRF);
                    fd.append('action', action);
                    for (var k in (fields || {})) fd.append(k, fields[k]);
                    return fetch('login.php', {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    }).then(function(r) {
                        return r.json().catch(function() {
                            return { success: false, message: 'Unexpected server response.' };
                        });
                    });
                }

                function explain(e) {
                    var n = e && e.name;
                    if (n === 'NotAllowedError') return 'The fingerprint prompt was cancelled or timed out. Please try again, or sign in with your password.';
                    if (n === 'SecurityError') return 'Fingerprint sign-in is not allowed on this web address. Please sign in with your password.';
                    if (n === 'NotSupportedError') return 'This device cannot be used for fingerprint sign-in.';
                    if (e && !(window.DOMException && e instanceof DOMException) && e.message) return e.message;
                    return 'Fingerprint sign-in failed. Please sign in with your password.';
                }

                btn.addEventListener('click', function() {
                    if (busy) return;
                    hide(errBox);
                    hide(okBox);
                    setState('loading');
                    api('wa_passkey_args').then(function(a) {
                        if (!a.success) return Promise.reject(new Error(a.message));
                        return navigator.credentials.get(decodeBin(a.args));
                    }).then(function(cred) {
                        if (!cred) return Promise.reject(new Error('No credential was returned.'));
                        return api('wa_passkey_verify', {
                            id: bufToB64(cred.rawId),
                            clientDataJSON: bufToB64(cred.response.clientDataJSON),
                            authenticatorData: bufToB64(cred.response.authenticatorData),
                            signature: bufToB64(cred.response.signature),
                            userHandle: cred.response.userHandle ? bufToB64(cred.response.userHandle) : ''
                        });
                    }).then(function(r) {
                        if (r.success && r.redirect) {
                            setState('success');
                            show(okBox, 'Fingerprint verified. Signing you in\u2026');
                            document.documentElement.classList.add('page-leaving');
                            setTimeout(function() { window.location.href = r.redirect; }, 450);
                            return;
                        }
                        return Promise.reject(new Error(r.message || 'Fingerprint sign-in failed.'));
                    }).catch(function(e) {
                        setState('idle');
                        show(errBox, explain(e));
                    });
                });
            })();
        </script>
    <?php endif; ?>
</body>

</html>