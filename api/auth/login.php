<?php
session_start();
require_once '../../config/database.php';
require_once '../../includes/security.php';

header('Content-Type: application/json');

// Block non-POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
    exit;
}

// CSRF check
if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    echo json_encode(['success' => false, 'error' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

$email    = trim($_POST['email']    ?? '');
$password = trim($_POST['password'] ?? '');

if (empty($email) || empty($password)) {
    echo json_encode(['success' => false, 'error' => 'Email and password are required.']);
    exit;
}

// Brute force protection (manual — no external function needed)
try {
    $database = new Database();
    $conn = $database->getConnection();

    // Check failed attempts in last 15 minutes
    $attemptStmt = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $attemptStmt->execute([$email]);
    $attempts = $attemptStmt->fetchColumn();

    if ($attempts >= 5) {
        echo json_encode(['success' => false, 'error' => 'Too many failed attempts. Please wait 15 minutes.']);
        exit;
    }

    // Get user
    $stmt = $conn->prepare("SELECT id, name, email, password_hash, role, status FROM users WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password_hash'])) {
        // Record failed attempt
        $logStmt = $conn->prepare("INSERT INTO login_attempts (username, ip_address, success, timestamp) VALUES (?, ?, 0, NOW())");
        $logStmt->execute([$email, $_SERVER['REMOTE_ADDR'] ?? '']);

        $new_csrf = generate_csrf_token();
        echo json_encode(['success' => false, 'error' => 'Invalid email or password.', 'csrf_token' => $new_csrf]);
        exit;
    }

    if ($user['status'] !== 'active') {
        echo json_encode(['success' => false, 'error' => 'Your account is inactive. Contact admin.']);
        exit;
    }

    // Record successful attempt
    $logStmt = $conn->prepare("INSERT INTO login_attempts (username, ip_address, success, timestamp) VALUES (?, ?, 1, NOW())");
    $logStmt->execute([$email, $_SERVER['REMOTE_ADDR'] ?? '']);

    // Set session
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['name']    = $user['name'];
    $_SESSION['email']   = $user['email'];
    $_SESSION['role']    = $user['role'];

    echo json_encode([
        'success' => true,
        'data'    => [
            'id'    => $user['id'],
            'name'  => $user['name'],
            'email' => $user['email'],
            'role'  => $user['role']
        ]
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
}