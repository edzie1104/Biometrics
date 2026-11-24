<?php
/* ═══════════════════════════════════════════════════════════════
   auth/security.php — Account security (fingerprint / passkey devices)
   • Only for users who are ALREADY signed in (username + password [+ 2-step]).
   • Adding or removing a device asks for the account password again.
   • Register several devices (one per phone / laptop) and remove any of them.
   Link to it from your dashboard:  <a href="../auth/security.php">Security</a>
═══════════════════════════════════════════════════════════════ */
require_once __DIR__ . '/mfa_helpers.php';
mfa_secure_session_start();
mfa_send_security_headers();
require_once __DIR__ . '/../config/db.php';

$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

/* ── must be signed in ───────────────────────────────────────── */
if (empty($_SESSION['user_id'])) {
    if ($isPost) mfa_json(['success' => false, 'message' => 'Your session expired. Please sign in again.', 'redirect' => 'login.php'], 401);
    header('Location: login.php');
    exit;
}
$uid = (int)$_SESSION['user_id'];
$st  = $pdo->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
$st->execute([$uid]);
$user = $st->fetch();
if (!$user || in_array($user['status'], ['Inactive', 'Pending'], true)) {
    $_SESSION = [];
    session_destroy();
    if ($isPost) mfa_json(['success' => false, 'message' => 'This account cannot use this page.', 'redirect' => 'login.php'], 403);
    header('Location: login.php');
    exit;
}

/* ── helpers ─────────────────────────────────────────────────── */
function sec_back_url(string $role, string $department): string
{
    switch ($role) {
        case 'Admin':
        case 'Project Coordinator':
        case 'Admin Support':
        case 'DTR Staff':
            return '../dtr/dtr.php';
        case 'Dept Head':
        case 'Staff':
            return trim($department) === '' ? '../index.php' : '../dtr/dtr.php';
        default:
            return '../index.php';
    }
}

function sec_cookie(string $name, ?string $value, int $expires): void
{
    setcookie($name, (string)$value, [
        'expires'  => $expires,
        'path'     => '/',
        'secure'   => mfa_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

/** Step-up: the account password must be typed again (rate-limited like the login). */
function sec_require_password($pdo, array $user): void
{
    if (mfa_is_locked($pdo, 'password', $user['username'])) {
        mfa_json(['success' => false, 'message' => 'Too many failed attempts. Please try again in ' . AUTH_LOCK_MINUTES . ' minutes.'], 429);
    }
    $pw = (string)($_POST['password'] ?? '');
    if ($pw === '' || !password_verify($pw, (string)$user['password'])) {
        mfa_log_attempt($pdo, 'password', $user['username'], (int)$user['id'], false);
        mfa_json(['success' => false, 'message' => 'Incorrect password.'], 403);
    }
    mfa_clear_failures($pdo, 'password', $user['username']);
}

/* ══════════════════════════════════════════════════════════════
   AJAX ACTIONS
══════════════════════════════════════════════════════════════ */
if ($isPost) {
    ob_start();
    if (!mfa_csrf_check($_POST['csrf'] ?? null)) {
        mfa_json(['success' => false, 'message' => 'Your session expired. Please reload the page.'], 403);
    }
    $action = (string)($_POST['action'] ?? '');
    try {
        switch ($action) {

            case 'wa_reg_args':
                if (!mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Fingerprint sign-in is not installed on this server yet.'], 400);
                }
                sec_require_password($pdo, $user);
                $creds = mfa_get_credentials($pdo, $uid);
                if (count($creds) >= WA_MAX_CREDENTIALS) {
                    mfa_json(['success' => false, 'message' => 'You reached the limit of ' . WA_MAX_CREDENTIALS . ' devices. Remove one first.'], 400);
                }
                $exclude = [];   // a device that is already registered cannot be registered twice
                foreach ($creds as $r) {
                    $bin = base64_decode((string)$r['credential_id'], true);
                    if ($bin !== false && $bin !== '') $exclude[] = $bin;
                }
                $wa   = mfa_webauthn();
                $args = $wa->getCreateArgs(
                    mfa_wa_user_handle($uid),
                    (string)$user['username'],
                    (string)($user['full_name'] ?: $user['username']),
                    60,
                    true,     // discoverable credential (passkey)
                    true,     // require user verification (fingerprint / face / PIN)
                    false,    // platform authenticator only (this device's own sensor)
                    $exclude
                );
                mfa_wa_store_challenge($wa, 'register');
                mfa_json(['success' => true, 'args' => $args]);

            case 'wa_reg_verify':
                if (!mfa_webauthn_available()) {
                    mfa_json(['success' => false, 'message' => 'Not available.'], 400);
                }
                $clientDataJSON    = base64_decode((string)($_POST['clientDataJSON'] ?? ''), true);
                $attestationObject = base64_decode((string)($_POST['attestationObject'] ?? ''), true);
                $challengeB64      = mfa_wa_take_challenge('register');
                if ($clientDataJSON === false || $attestationObject === false) {
                    mfa_json(['success' => false, 'message' => 'Invalid registration data.'], 400);
                }
                if ($challengeB64 === '') {
                    mfa_json(['success' => false, 'message' => 'The registration request expired. Please try again.'], 400);
                }
                try {
                    mfa_wa_assert_origin($clientDataJSON);
                    $wa   = mfa_webauthn();
                    $data = $wa->processCreate(
                        $clientDataJSON,
                        $attestationObject,
                        mfa_bytebuffer(base64_decode($challengeB64)),
                        true,    // require user verification
                        true,    // require user presence
                        false,   // platform authenticators have no public attestation root
                        false
                    );
                    $label = mfa_wa_clean_label((string)($_POST['label'] ?? ''));
                    mfa_wa_save_credential($pdo, $uid, $data, $label !== '' ? $label : mfa_wa_device_label());
                    sec_cookie('wa_device', '1', time() + 86400 * 365);
                    mfa_json(['success' => true]);
                } catch (Throwable $e) {
                    error_log('security.php registration failed: ' . $e->getMessage());
                    mfa_json(['success' => false, 'message' => 'Could not register this device. Please try again.'], 400);
                }

            case 'wa_revoke':
                sec_require_password($pdo, $user);
                $id = (int)($_POST['id'] ?? 0);
                $d  = $pdo->prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?");   // ownership enforced
                $d->execute([$id, $uid]);
                if ($d->rowCount() !== 1) {
                    mfa_json(['success' => false, 'message' => 'That device was not found.'], 404);
                }
                if (count(mfa_get_credentials($pdo, $uid)) === 0) sec_cookie('wa_device', null, time() - 3600);
                mfa_json(['success' => true]);

            default:
                mfa_json(['success' => false, 'message' => 'Unknown action.'], 400);
        }
    } catch (Throwable $e) {
        error_log('security.php error: ' . $e->getMessage());
        mfa_json(['success' => false, 'message' => 'Something went wrong. Please try again.'], 500);
    }
}

/* ══════════════════════════════════════════════════════════════
   PAGE
══════════════════════════════════════════════════════════════ */
$creds     = mfa_get_credentials($pdo, $uid);
usort($creds, function ($a, $b) { return strcmp((string)$a['created_at'], (string)$b['created_at']); });
$libReady  = mfa_webauthn_available();
$backUrl   = sec_back_url((string)$user['role'], (string)$user['department']);
$fmt       = function ($t) { return $t ? date('M j, Y g:i A', strtotime((string)$t)) : 'Never'; };
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Account Security — Staff Monitoring</title>
    <style>
        :root {
            --bg: #fdf3ea;
            --card: #ffffff;
            --ink: #2b1a10;
            --muted: #7a6455;
            --line: rgba(122, 46, 14, .14);
            --a: #c2410c;
            --b: #ea580c;
            --ok: #15803d;
            --bad: #b91c1c;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0f1020;
                --card: #181a33;
                --ink: #eef0ff;
                --muted: #a5a9cf;
                --line: rgba(255, 255, 255, .12);
                --a: #6d5dfc;
                --b: #8b7bff;
                --ok: #4ade80;
                --bad: #f87171;
            }
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            min-height: 100vh;
            background: var(--bg);
            color: var(--ink);
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            padding: 24px 16px 48px
        }

        .wrap {
            max-width: 680px;
            margin: 0 auto
        }

        .back {
            display: inline-block;
            margin-bottom: 14px;
            color: var(--a);
            text-decoration: none;
            font-weight: 600;
            font-size: .9rem
        }

        .card {
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 26px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, .10)
        }

        h1 {
            margin: 0 0 4px;
            font-size: 1.35rem
        }

        h2 {
            margin: 26px 0 10px;
            font-size: 1rem
        }

        p.lead {
            margin: 0 0 18px;
            color: var(--muted);
            font-size: .9rem;
            line-height: 1.55
        }

        .msg {
            display: none;
            border-radius: 12px;
            padding: 11px 14px;
            margin: 0 0 14px;
            font-size: .88rem;
            line-height: 1.45
        }

        .msg.err {
            display: block;
            background: rgba(239, 68, 68, .12);
            border: 1px solid rgba(239, 68, 68, .3);
            color: var(--bad)
        }

        .msg.ok {
            display: block;
            background: rgba(34, 197, 94, .12);
            border: 1px solid rgba(34, 197, 94, .3);
            color: var(--ok)
        }

        .msg.warn {
            display: block;
            background: rgba(245, 158, 11, .14);
            border: 1px solid rgba(245, 158, 11, .35);
            color: var(--ink)
        }

        label {
            display: block;
            font-size: .72rem;
            font-weight: 700;
            letter-spacing: .06em;
            text-transform: uppercase;
            color: var(--muted);
            margin: 0 0 6px
        }

        input[type=password],
        input[type=text] {
            width: 100%;
            padding: 12px 14px;
            border-radius: 12px;
            border: 1.5px solid var(--line);
            background: transparent;
            color: var(--ink);
            font: inherit
        }

        input:focus {
            outline: none;
            border-color: var(--a);
            box-shadow: 0 0 0 3px rgba(194, 65, 12, .15)
        }

        .row {
            display: grid;
            gap: 12px;
            grid-template-columns: 1fr 1fr
        }

        @media(max-width:520px) {
            .row {
                grid-template-columns: 1fr
            }
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            border: 0;
            cursor: pointer;
            padding: 13px 18px;
            border-radius: 13px;
            font: inherit;
            font-weight: 700;
            color: #fff;
            background: linear-gradient(125deg, var(--a), var(--b));
            box-shadow: 0 6px 20px rgba(0, 0, 0, .18);
            transition: transform .15s, filter .15s
        }

        .btn:hover:not(:disabled) {
            transform: translateY(-2px);
            filter: brightness(1.07)
        }

        .btn:disabled {
            opacity: .6;
            cursor: progress
        }

        .btn.full {
            width: 100%;
            margin-top: 14px
        }

        .btn svg {
            width: 22px;
            height: 22px
        }

        .btn.busy svg {
            animation: pulse 1s ease-in-out infinite
        }

        @keyframes pulse {

            0%,
            100% {
                opacity: 1
            }

            50% {
                opacity: .35
            }
        }

        .dev {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 13px 14px;
            border: 1px solid var(--line);
            border-radius: 14px;
            margin-bottom: 10px
        }

        .dev .ic {
            flex: 0 0 38px;
            height: 38px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            color: #fff;
            background: linear-gradient(135deg, var(--a), var(--b))
        }

        .dev .ic svg {
            width: 20px;
            height: 20px
        }

        .dev .tx {
            flex: 1;
            min-width: 0
        }

        .dev b {
            display: block;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap
        }

        .dev small {
            color: var(--muted);
            font-size: .76rem
        }

        .rm {
            border: 1.5px solid rgba(239, 68, 68, .45);
            background: transparent;
            color: var(--bad);
            padding: 8px 12px;
            border-radius: 10px;
            font: inherit;
            font-size: .82rem;
            font-weight: 700;
            cursor: pointer
        }

        .rm:hover:not(:disabled) {
            background: rgba(239, 68, 68, .1)
        }

        .empty {
            color: var(--muted);
            font-size: .9rem;
            padding: 6px 2px 2px
        }

        .tip {
            font-size: .8rem;
            color: var(--muted);
            line-height: 1.55;
            margin-top: 12px
        }
    </style>
</head>

<body>
    <div class="wrap">
        <a class="back" href="<?= mfa_e($backUrl) ?>">&larr; Back to dashboard</a>
        <div class="card">
            <h1>Account security</h1>
            <p class="lead">Signed in as <strong><?= mfa_e($user['full_name'] ?: $user['username']) ?></strong> (<?= mfa_e($user['role']) ?>).
                Register this device's fingerprint, face or screen lock so you can sign in with one touch. Your fingerprint never leaves your device &mdash; this site only stores a public key.</p>

            <div id="msg" class="msg" role="status" aria-live="polite"></div>

            <?php if (!$libReady): ?>
                <div class="msg warn">Fingerprint sign-in is not installed on this server yet (the WebAuthn library is missing). Ask the administrator to follow the setup guide.</div>
            <?php endif; ?>

            <h2>Registered devices</h2>
            <div id="devList">
                <?php if (!$creds): ?>
                    <p class="empty">No device registered yet.</p>
                <?php endif; ?>
                <?php foreach ($creds as $c): ?>
                    <div class="dev" data-id="<?= (int)$c['id'] ?>">
                        <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
                                <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
                                <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
                                <path d="M2 12a10 10 0 0 1 18-6" />
                                <path d="M2 16h.01" />
                                <path d="M21.8 16c.2-2 .131-5.354 0-6" />
                                <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
                                <path d="M8.65 22c.21-.66.45-1.32.57-2" />
                                <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
                            </svg></span>
                        <span class="tx"><b><?= mfa_e($c['label']) ?></b><small>Added <?= mfa_e($fmt($c['created_at'])) ?> &middot; Last used <?= mfa_e($fmt($c['last_used_at'])) ?></small></span>
                        <button type="button" class="rm" data-id="<?= (int)$c['id'] ?>">Remove</button>
                    </div>
                <?php endforeach; ?>
            </div>

            <h2>Add or remove a device</h2>
            <div class="row">
                <div>
                    <label for="pw">Confirm your password</label>
                    <input type="password" id="pw" autocomplete="current-password" placeholder="Your account password">
                </div>
                <div>
                    <label for="lbl">Device name (optional)</label>
                    <input type="text" id="lbl" maxlength="40" placeholder="e.g. Office laptop">
                </div>
            </div>
            <button type="button" class="btn full" id="regBtn" <?= $libReady ? '' : 'disabled' ?>>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
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
                <span id="regTxt">Register this device's fingerprint</span>
            </button>
            <p class="tip">To add another phone or laptop, sign in on that device and open this page there. Removing a device immediately stops it from signing in. Fingerprint sign-in needs HTTPS and a device with a fingerprint, face or screen-lock sensor.</p>
        </div>
    </div>

    <script>
        (function() {
            'use strict';
            var CSRF = <?= json_encode(mfa_csrf_token()) ?>;
            var $ = function(id) {
                return document.getElementById(id);
            };
            var regBtn = $('regBtn'),
                regTxt = $('regTxt'),
                pw = $('pw');
            var IDLE = regTxt.textContent;

            function say(text, kind) {
                var m = $('msg');
                m.className = 'msg ' + (kind || 'err');
                m.textContent = text;
                m.scrollIntoView({
                    behavior: 'smooth',
                    block: 'nearest'
                });
            }

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
                return fetch('security.php', {
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
                }).then(function(j) {
                    if (j && j.redirect && !j.success) {
                        window.location.href = j.redirect;
                    }
                    return j;
                });
            }

            function explain(e) {
                var n = e && e.name;
                if (n === 'InvalidStateError') return 'This device is already registered on your account. Remove it first if you want to register it again.';
                if (n === 'NotAllowedError') return 'The fingerprint prompt was cancelled or timed out. Please try again.';
                if (n === 'SecurityError') return 'Fingerprint registration is not allowed on this web address (HTTPS and a correct RP ID are required).';
                if (n === 'NotSupportedError') return 'This device cannot create a fingerprint passkey.';
                if (e && !(window.DOMException && e instanceof DOMException) && e.message) return e.message;
                return 'Registration failed. Please try again.';
            }

            if (regBtn) {
                regBtn.addEventListener('click', function() {
                    if (!window.isSecureContext) {
                        say('Fingerprint registration needs a secure (HTTPS) connection.');
                        return;
                    }
                    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
                        say('This browser or device does not support fingerprint (passkey) registration.');
                        return;
                    }
                    if (!pw.value) {
                        say('Please type your password first.');
                        pw.focus();
                        return;
                    }
                    regBtn.disabled = true;
                    regBtn.classList.add('busy');
                    regTxt.textContent = 'Touch your fingerprint sensor to continue\u2026';
                    api('wa_reg_args', {
                        password: pw.value
                    }).then(function(a) {
                        if (!a.success) return Promise.reject(new Error(a.message));
                        return navigator.credentials.create(decodeBin(a.args));
                    }).then(function(cred) {
                        if (!cred) return Promise.reject(new Error('No credential was returned.'));
                        return api('wa_reg_verify', {
                            clientDataJSON: bufToB64(cred.response.clientDataJSON),
                            attestationObject: bufToB64(cred.response.attestationObject),
                            label: $('lbl').value
                        });
                    }).then(function(r) {
                        if (!r.success) return Promise.reject(new Error(r.message));
                        pw.value = '';
                        say('Fingerprint registered. You can now use "Sign in with fingerprint" on the login page.', 'ok');
                        setTimeout(function() {
                            window.location.reload();
                        }, 1100);
                    }).catch(function(e) {
                        say(explain(e));
                        regBtn.disabled = false;
                        regBtn.classList.remove('busy');
                        regTxt.textContent = IDLE;
                    });
                });
            }

            document.querySelectorAll('.rm').forEach(function(b) {
                b.addEventListener('click', function() {
                    if (!pw.value) {
                        say('Type your password above to confirm removing a device.');
                        pw.focus();
                        return;
                    }
                    if (!window.confirm('Remove this device? It will no longer be able to sign in with a fingerprint.')) return;
                    b.disabled = true;
                    api('wa_revoke', {
                        id: b.getAttribute('data-id'),
                        password: pw.value
                    }).then(function(r) {
                        if (!r.success) {
                            b.disabled = false;
                            say(r.message || 'Could not remove the device.');
                            return;
                        }
                        pw.value = '';
                        say('Device removed.', 'ok');
                        var row = b.closest('.dev');
                        if (row) row.remove();
                        if (!document.querySelector('.dev')) {
                            $('devList').innerHTML = '<p class="empty">No device registered yet.</p>';
                        }
                    });
                });
            });
        })();
    </script>
</body>

</html>
