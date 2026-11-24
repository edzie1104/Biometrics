<?php
/* ═══════════════════════════════════════════════════════════════
   auth/terms_agreement.php
   Called by the Terms & Conditions modal in login.php (AJAX).
   action=agree   → saves the agreement, completes the login, returns {success, action:'agreed', redirect}
   action=decline → cancels the pending login
═══════════════════════════════════════════════════════════════ */
require_once __DIR__ . '/mfa_helpers.php';
require_once __DIR__ . '/../config/db.php';

mfa_secure_session_start();
mfa_send_security_headers();
header('Content-Type: application/json; charset=utf-8');

function t_out(array $d, int $code = 200): void
{
    http_response_code($code);
    echo json_encode($d);
    exit;
}

function t_destination(string $role, string $department = ''): string
{
    switch ($role) {
        case 'Admin':
        case 'Project Coordinator':
        case 'Admin Support':
        case 'DTR Staff':
            return '../dtr/dtr.php';
        case 'Dept Head':
        case 'Staff':
            return trim($department) === '' ? '' : '../dtr/dtr.php';
        default:
            return '../index.php';
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    t_out(['success' => false, 'message' => 'Invalid request.'], 405);
}

// Same-origin only (the modal sends no CSRF token, so block cross-site posts here)
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? '')) {
    t_out(['success' => false, 'message' => 'Forbidden.'], 403);
}

$action = (string)($_POST['action'] ?? '');
$uid    = (int)($_SESSION['terms_pending_user_id'] ?? 0);

if ($action === 'decline') {
    unset($_SESSION['terms_pending_user_id'], $_SESSION['terms_pending_data']);
    t_out(['success' => true, 'action' => 'declined']);
}

if ($action !== 'agree') {
    t_out(['success' => false, 'message' => 'Unknown action.'], 400);
}

if ($uid <= 0) {
    t_out(['success' => false, 'message' => 'Your sign-in session expired. Please sign in again.'], 401);
}

try {
    $s = $pdo->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
    $s->execute([$uid]);
    $user = $s->fetch();
    if (!$user || in_array($user['status'], ['Inactive', 'Pending'], true)) {
        unset($_SESSION['terms_pending_user_id'], $_SESSION['terms_pending_data']);
        t_out(['success' => false, 'message' => 'This account cannot sign in.'], 403);
    }

    // current terms version
    $v = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'terms_version' LIMIT 1");
    $version = $v ? ($v->fetchColumn() ?: '1.0') : '1.0';

    $pdo->prepare("INSERT INTO terms_agreements (user_id, terms_version, agreement_status, ip_address) VALUES (?, ?, 'Agreed', ?)")
        ->execute([$uid, $version, mfa_client_ip()]);

    // Complete the real login
    session_regenerate_id(true);
    unset($_SESSION['terms_pending_user_id'], $_SESSION['terms_pending_data']);
    $_SESSION['csrf']       = bin2hex(random_bytes(32));
    $_SESSION['user_id']    = $user['id'];
    $_SESSION['username']   = $user['username'];
    $_SESSION['full_name']  = $user['full_name'];
    $_SESSION['role']       = $user['role'];
    $_SESSION['department'] = $user['department'];
    $_SESSION['photo']      = $user['photo'] ?? '';

    $dest = t_destination((string)$user['role'], (string)$user['department']);
    if ($dest === '') {
        session_destroy();
        $dest = 'login.php?error=nodepartment';
    }
    t_out(['success' => true, 'action' => 'agreed', 'redirect' => $dest]);
} catch (Throwable $e) {
    error_log('terms_agreement.php: ' . $e->getMessage());
    t_out(['success' => false, 'message' => 'Could not save your agreement. Check that the terms_agreements table exists (run setup_all.sql).'], 500);
}
