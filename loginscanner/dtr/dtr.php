<?php
/* PLACEHOLDER dashboard so you can see a successful login.
   >>> If you already have your own dtr/dtr.php, DO NOT copy this file. <<< */
session_start();
if (empty($_SESSION['user_id'])) { header('Location: ../auth/login.php'); exit; }
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard</title>
<style>body{font-family:system-ui,sans-serif;background:#fdf3ea;display:grid;place-items:center;min-height:100vh;margin:0}
.c{background:#fff;padding:36px 44px;border-radius:18px;box-shadow:0 10px 40px rgba(0,0,0,.12);text-align:center}
h1{color:#7a2e0e;margin:0 0 8px}a{display:inline-block;margin-top:18px;padding:10px 22px;background:#e8590c;color:#fff;border-radius:10px;text-decoration:none;font-weight:700}</style></head>
<body><div class="c"><h1>✅ Login successful</h1>
<p>Welcome, <b><?= $e($_SESSION['full_name'] ?: $_SESSION['username']) ?></b><br>Role: <?= $e($_SESSION['role']) ?></p>
<a href="../auth/logout.php">Log out</a></div></body></html>
