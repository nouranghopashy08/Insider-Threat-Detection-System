<?php
// config.php - Database Configuration
session_start();

$host = 'localhost';
$dbname = 'InsiderThreatDB';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Handle Login
if (isset($_POST['login'])) {
    $loginUsername = $_POST['username'];
    $loginPassword = $_POST['password'];
    
    // Check if user exists in database
    $stmt = $pdo->prepare("SELECT * FROM Users WHERE username = ?");
    $stmt->execute([$loginUsername]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Verify the password against the stored hash (real authentication check)
    if ($user && $user['status'] == 'Active' && password_verify($loginPassword, $user['p_hash'])) {
        // Regenerate the session ID on login to prevent session fixation
        session_regenerate_id(true);

        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['full_name'] = $user['full_name'];
        $_SESSION['role'] = $user['role'];
        
        // Update last login
        $updateStmt = $pdo->prepare("UPDATE Users SET last_login = NOW() WHERE user_id = ?");
        $updateStmt->execute([$user['user_id']]);
        
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    } else {
        $loginError = "Invalid username or password!";
    }
}

// Handle Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    // Show Login Page
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Insider Threat Detection System</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #000000ff 0%, #7b5f97ff 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }

            .login-container {
                background: black;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }

            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }

            .login-header h1 {
                color: #dee0e6ff;
                font-size: 28px;
                margin-bottom: 10px;
            }

            .login-header p {
                color: #6b7280;
                font-size: 14px;
            }

            .form-group {
                margin-bottom: 20px;
            }

            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #b3b4b6ff;
                font-weight: 500;
            }

            .form-control {
                width: 100%;
                padding: 12px;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                font-size: 14px;
                transition: all 0.3s;
            }

            .form-control:focus {
                outline: none;
                border-color: #3b82f6;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
            }

            .btn-login {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }

            .btn-login:hover {
                transform: translateY(-2px);
            }

            .error-message {
                background: #ff0000ff;
                color: #f1f1f1ff;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
            }

        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🛡️ Threat Monitor</h1>
                <p>Insider Threat Detection System</p>
            </div>

            <?php if (isset($loginError)): ?>
                <div class="error-message">
                    <?php echo htmlspecialchars($loginError); ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" class="form-control" required autofocus>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                </div>

                <button type="submit" name="login" class="btn-login">Login</button>
            </form>

        </div>
    </body>
    </html>
    <?php
    exit();
}

// Generate a CSRF token for this session if one doesn't exist yet
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Verify CSRF token on every POST request before any action handler runs
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid or missing security token. Please refresh the page and try again.');
    }
}

// Handle Actions
$actionMessage = '';

// Add User
if (isset($_POST['add_user'])) {
    // Only administrators can create new users
    if ($_SESSION['role'] !== 'System Administrator') {
        die('You do not have permission to add users.');
    }
    // Hash the password before storing it — never store plaintext passwords
    $hashedPassword = password_hash($_POST['password'], PASSWORD_DEFAULT);
    // Clamp privilege level to 1-5 regardless of what was submitted
    $privilegeLevel = max(1, min(5, (int)$_POST['privilege_level']));

    $stmt = $pdo->prepare("INSERT INTO Users (username, full_name, role, department, email, status, last_login, privilege_level, p_hash) VALUES (?, ?, ?, ?, ?, 'Active', NOW(), ?, ?)");
    $stmt->execute([
        $_POST['username'],
        $_POST['full_name'],
        $_POST['role'],
        $_POST['department'],
        $_POST['email'],
        $privilegeLevel,
        $hashedPassword
    ]);
    $actionMessage = "User added successfully!";
}

// Update User Status
if (isset($_POST['update_user_status'])) {
    // Only administrators can enable/disable accounts
    if ($_SESSION['role'] !== 'System Administrator') {
        die('You do not have permission to change user status.');
    }
    $stmt = $pdo->prepare("UPDATE Users SET status = ? WHERE user_id = ?");
    $stmt->execute([$_POST['status'], $_POST['user_id']]);
    $actionMessage = "User status updated successfully!";
}

// Add Alert
if (isset($_POST['add_alert'])) {
    $stmt = $pdo->prepare("INSERT INTO Alerts (user_id, level_id, alert_type, alert_message, status, created_at) VALUES (?, ?, ?, ?, 'Open', NOW())");
    $stmt->execute([
        $_POST['user_id'],
        $_POST['level_id'],
        $_POST['alert_type'],
        $_POST['alert_message']
    ]);
    $actionMessage = "Alert created successfully!";
}

// Update Alert Status
if (isset($_POST['update_alert_status'])) {
    $stmt = $pdo->prepare("UPDATE Alerts SET status = ? WHERE alert_id = ?");
    $stmt->execute([$_POST['status'], $_POST['alert_id']]);
    $actionMessage = "Alert status updated successfully!";
}

// Add Investigation
if (isset($_POST['add_investigation'])) {
    $stmt = $pdo->prepare("INSERT INTO Investigations (alert_id, investigator_name, investigation_status, findings, started_at) VALUES (?, ?, 'Open', ?, NOW())");
    $stmt->execute([
        $_POST['alert_id'],
        $_SESSION['full_name'],
        $_POST['findings']
    ]);
    $actionMessage = "Investigation started successfully!";
}

// Update Investigation
if (isset($_POST['update_investigation'])) {
    // Only security staff can update or close an investigation
    if (!in_array($_SESSION['role'], ['System Administrator', 'IT Security'])) {
        die('You do not have permission to update investigations.');
    }
    $closedAt = $_POST['investigation_status'] == 'Closed' ? ", closed_at = NOW()" : "";
    $stmt = $pdo->prepare("UPDATE Investigations SET investigation_status = ?, findings = ? $closedAt WHERE investigation_id = ?");
    $stmt->execute([
        $_POST['investigation_status'],
        $_POST['findings'],
        $_POST['investigation_id']
    ]);
    $actionMessage = "Investigation updated successfully!";
}

// Add Device
if (isset($_POST['add_device'])) {
    $stmt = $pdo->prepare("INSERT INTO Devices (user_id, hostname, ip_address, os, status, registered_at) VALUES (?, ?, ?, ?, 'Active', NOW())");
    $stmt->execute([
        $_POST['user_id'],
        $_POST['hostname'],
        $_POST['ip_address'],
        $_POST['os']
    ]);
    $actionMessage = "Device registered successfully!";
}

// Add Suspicious Action
if (isset($_POST['add_suspicious'])) {
    $stmt = $pdo->prepare("INSERT INTO SuspiciousActions (user_id, device_id, action_type, raw_source, action_description, timestamp, severity) VALUES (?, ?, ?, ?, ?, NOW(), ?)");
    $stmt->execute([
        $_POST['user_id'],
        $_POST['device_id'],
        $_POST['action_type'],
        $_POST['raw_source'],
        $_POST['action_description'],
        $_POST['severity']
    ]);
    $actionMessage = "Suspicious action logged successfully!";
}

// Update Behavior Score
if (isset($_POST['update_behavior_score'])) {
    // Only security staff can recalculate a user's risk score
    if (!in_array($_SESSION['role'], ['System Administrator', 'IT Security'])) {
        die('You do not have permission to update behavior scores.');
    }
    $total = $_POST['login_anomaly_score'] + $_POST['file_access_score'] + $_POST['device_score'];
    
    // Check if score exists
    $checkStmt = $pdo->prepare("SELECT score_id FROM BehaviorScores WHERE user_id = ?");
    $checkStmt->execute([$_POST['user_id']]);
    
    if ($checkStmt->fetch()) {
        $stmt = $pdo->prepare("UPDATE BehaviorScores SET login_anomaly_score = ?, file_access_score = ?, device_score = ?, total_score = ?, calculated_at = NOW() WHERE user_id = ?");
        $stmt->execute([
            $_POST['login_anomaly_score'],
            $_POST['file_access_score'],
            $_POST['device_score'],
            $total,
            $_POST['user_id']
        ]);
    } else {
        $stmt = $pdo->prepare("INSERT INTO BehaviorScores (user_id, login_anomaly_score, file_access_score, device_score, total_score, calculated_at) VALUES (?, ?, ?, ?, ?, NOW())");
        $stmt->execute([
            $_POST['user_id'],
            $_POST['login_anomaly_score'],
            $_POST['file_access_score'],
            $_POST['device_score'],
            $total
        ]);
    }
    $actionMessage = "Behavior score updated successfully!";
}

// Get current page
$page = isset($_GET['page']) ? $_GET['page'] : 'dashboard';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insider Threat Detection System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0b0bff;
            color: #7c7a7aff;
        }

        .container {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            width: 250px;
            background: linear-gradient(180deg, #12133aff 0%, #070713ff 100%);
            color: white;
            padding: 20px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }

        .sidebar-header {
            padding: 0 20px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 20px;
        }

        .sidebar-header h2 {
            font-size: 18px;
            margin-bottom: 5px;
        }

        .sidebar-header p {
            font-size: 12px;
            opacity: 0.8;
        }

        .user-info {
            padding: 15px 20px;
            background: rgba(255,255,255,0.1);
            margin-bottom: 20px;
        }

        .user-info p {
            font-size: 13px;
            margin-bottom: 5px;
        }

        .user-info small {
            opacity: 0.8;
        }

        .nav-menu {
            list-style: none;
        }

        .nav-menu li a {
            display: block;
            padding: 12px 20px;
            color: white;
            text-decoration: none;
            transition: all 0.3s;
            border-left: 3px solid transparent;
        }

        .nav-menu li a:hover,
        .nav-menu li a.active {
            background: rgba(86, 82, 82, 0.1);
            border-left-color: #5b5f64ff;
        }

        .logout-btn {
            margin: 20px;
            padding: 10px;
            background: rgba(239, 68, 68, 0.8);
            color: white;
            text-align: center;
            border-radius: 6px;
            text-decoration: none;
            display: block;
            transition: all 0.3s;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 1);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 250px;
            padding: 30px;
        }

        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .header h1 {
            color: #1e3a8a;
            font-size: 28px;
        }

        /* Success Message */
        .success-message {
            background: #d1fae5;
            color: #065f46;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #10b981;
        }

        /* Dashboard Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 4px solid #3b82f6;
        }

        .stat-card.warning {
            border-left-color: #f59e0b;
        }

        .stat-card.danger {
            border-left-color: #ef4444;
        }

        .stat-card.success {
            border-left-color: #10b981;
        }

        .stat-card h3 {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
            color: #1e3a8a;
        }

        /* Tables */
        .table-container {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }

        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .table-header h2 {
            color: #1e3a8a;
            font-size: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        table thead {
            background: #f9fafb;
        }

        table th {
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 2px solid #e5e7eb;
        }

        table td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }

        table tbody tr:hover {
            background: #f9fafb;
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-low {
            background: #d1fae5;
            color: #065f46;
        }

        .badge-medium {
            background: #fed7aa;
            color: #92400e;
        }

        .badge-high {
            background: #fecaca;
            color: #991b1b;
        }

        .badge-critical {
            background: #dc2626;
            color: white;
        }

        .badge-success {
            background: #d1fae5;
            color: #065f46;
        }

        .badge-active {
            background: #d1fae5;
            color: #065f46;
        }

        .badge-disabled {
            background: #e5e7eb;
            color: #6b7280;
        }

        .badge-warning {
            background: #fef3c7;
            color: #92400e;
        }

        .badge-open {
            background: #dbeafe;
            color: #1e40af;
        }

        .badge-investigating {
            background: #fed7aa;
            color: #92400e;
        }

        .badge-inprogress {
            background: #fed7aa;
            color: #92400e;
        }

        .badge-closed {
            background: #d1fae5;
            color: #065f46;
        }

        .badge-allowed {
            background: #d1fae5;
            color: #065f46;
        }

        .badge-blocked {
            background: #fecaca;
            color: #991b1b;
        }

        .badge-flagged {
            background: #fed7aa;
            color: #92400e;
        }

        /* Buttons */
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }

        .btn-primary {
            background: #3b82f6;
            color: white;
        }

        .btn-primary:hover {
            background: #2563eb;
        }

        .btn-success {
            background: #10b981;
            color: white;
        }

        .btn-success:hover {
            background: #059669;
        }

        .btn-warning {
            background: #f59e0b;
            color: white;
        }

        .btn-warning:hover {
            background: #d97706;
        }

        .btn-danger {
            background: #ef4444;
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }

        /* Forms */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #374151;
            font-weight: 500;
        }

        .form-control {
            width: 100%;
            padding: 10px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
        }

        .form-control:focus {
            outline: none;
            border-color: #3b82f6;
        }

        select.form-control {
            cursor: pointer;
        }

        textarea.form-control {
            resize: vertical;
            min-height: 80px;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            overflow-y: auto;
        }

        .modal.active {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            max-width: 600px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e5e7eb;
        }

        .modal-header h2 {
            color: #1e3a8a;
            font-size: 22px;
        }

        .close-modal {
            background: none;
            border: none;
            font-size: 28px;
            cursor: pointer;
            color: #6b7280;
            line-height: 1;
        }

        .close-modal:hover {
            color: #1e3a8a;
        }

        .action-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <h2>🛡️ Threat Monitor</h2>
                <p>Insider Threat Detection</p>
            </div>

            <div class="user-info">
                <p><strong><?php echo htmlspecialchars($_SESSION['full_name']); ?></strong></p>
                <small><?php echo htmlspecialchars($_SESSION['role']); ?></small><br>
                <small><?php echo htmlspecialchars($_SESSION['username']); ?></small>
            </div>

            <ul class="nav-menu">
                <li><a href="?page=dashboard" class="<?php echo $page == 'dashboard' ? 'active' : ''; ?>">📊 Dashboard</a></li>
                <li><a href="?page=users" class="<?php echo $page == 'users' ? 'active' : ''; ?>">👥 Users</a></li>
                <li><a href="?page=alerts" class="<?php echo $page == 'alerts' ? 'active' : ''; ?>">🚨 Alerts</a></li>
                <li><a href="?page=investigations" class="<?php echo $page == 'investigations' ? 'active' : ''; ?>">🔍 Investigations</a></li>
                <li><a href="?page=suspicious" class="<?php echo $page == 'suspicious' ? 'active' : ''; ?>">⚠️ Suspicious Actions</a></li>
                <li><a href="?page=devices" class="<?php echo $page == 'devices' ? 'active' : ''; ?>">💻 Devices</a></li>
                <li><a href="?page=logins" class="<?php echo $page == 'logins' ? 'active' : ''; ?>">🔐 Login History</a></li>
                <li><a href="?page=files" class="<?php echo $page == 'files' ? 'active' : ''; ?>">📁 File Access</a></li>
            </ul>

            <a href="?logout" class="logout-btn">Logout</a>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <?php if ($actionMessage): ?>
                <div class="success-message">
                    ✓ <?php echo $actionMessage; ?>
                </div>
            <?php endif; ?>

            <?php
            // Dashboard Page
            if ($page == 'dashboard') {
                $totalUsers = $pdo->query("SELECT COUNT(*) FROM Users WHERE status='Active'")->fetchColumn();
                $openAlerts = $pdo->query("SELECT COUNT(*) FROM Alerts WHERE status='Open'")->fetchColumn();
                $criticalAlerts = $pdo->query("SELECT COUNT(*) FROM Alerts WHERE level_id=4")->fetchColumn();
                $highRiskUsers = $pdo->query("SELECT COUNT(*) FROM BehaviorScores WHERE total_score >= 100")->fetchColumn();
                ?>
                
                <div class="header">
                    <h1>Security Dashboard</h1>
                </div>

                <div class="stats-grid">
                    <div class="stat-card success">
                        <h3>Active Users</h3>
                        <div class="number"><?php echo $totalUsers; ?></div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Open Alerts</h3>
                        <div class="number"><?php echo $openAlerts; ?></div>
                    </div>
                    <div class="stat-card danger">
                        <h3>Critical Alerts</h3>
                        <div class="number"><?php echo $criticalAlerts; ?></div>
                    </div>
                    <div class="stat-card danger">
                        <h3>High Risk Users</h3>
                        <div class="number"><?php echo $highRiskUsers; ?></div>
                    </div>
                </div>

                <?php
                $recentAlerts = $pdo->query("
                    SELECT a.*, u.username, u.full_name, r.level_name 
                    FROM Alerts a 
                    JOIN Users u ON a.user_id = u.user_id 
                    JOIN RiskLevels r ON a.level_id = r.level_id 
                    ORDER BY a.created_at DESC 
                    LIMIT 10
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="table-container">
                    <div class="table-header">
                        <h2>Recent Alerts</h2>
                        <a href="?page=alerts" class="btn btn-primary btn-sm">View All</a>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Type</th>
                                <th>Message</th>
                                <th>Risk Level</th>
                                <th>Status</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recentAlerts as $alert): ?>
                            <tr>
                                <td>#<?php echo $alert['alert_id']; ?></td>
                                <td><?php echo htmlspecialchars($alert['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($alert['alert_type']); ?></td>
                                <td><?php echo htmlspecialchars($alert['alert_message']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($alert['level_name']); ?>"><?php echo $alert['level_name']; ?></span></td>
                                <td><span class="badge badge-<?php echo strtolower($alert['status']); ?>"><?php echo $alert['status']; ?></span></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($alert['created_at'])); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'users') {
                $users = $pdo->query("
                    SELECT u.*, b.total_score, b.calculated_at 
                    FROM Users u 
                    LEFT JOIN BehaviorScores b ON u.user_id = b.user_id 
                    ORDER BY b.total_score DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>User Management</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Users</h2>
                        <div class="action-buttons">
                            <button onclick="openModal('addUserModal')" class="btn btn-primary btn-sm">+ Add User</button>
                            <button onclick="openModal('updateScoreModal')" class="btn btn-warning btn-sm">Update Risk Score</button>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Full Name</th>
                                <th>Department</th>
                                <th>Role</th>
                                <th>Privilege</th>
                                <th>Risk Score</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo $user['user_id']; ?></td>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($user['department']); ?></td>
                                <td><?php echo htmlspecialchars($user['role']); ?></td>
                                <td><?php echo $user['privilege_level']; ?></td>
                                <td>
                                    <?php 
                                    $score = $user['total_score'] ?? 0;
                                    $badgeClass = $score >= 200 ? 'critical' : ($score >= 100 ? 'high' : ($score >= 50 ? 'medium' : 'low'));
                                    ?>
                                    <span class="badge badge-<?php echo $badgeClass; ?>"><?php echo $score; ?></span>
                                </td>
                                <td><span class="badge badge-<?php echo strtolower($user['status']); ?>"><?php echo $user['status']; ?></span></td>
                                <td>
                                    <button onclick="changeUserStatus(<?php echo $user['user_id']; ?>, '<?php echo $user['status']; ?>')" class="btn btn-sm <?php echo $user['status'] == 'Active' ? 'btn-danger' : 'btn-success'; ?>">
                                        <?php echo $user['status'] == 'Active' ? 'Disable' : 'Enable'; ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'alerts') {
                $alerts = $pdo->query("
                    SELECT a.*, u.username, u.full_name, r.level_name 
                    FROM Alerts a 
                    JOIN Users u ON a.user_id = u.user_id 
                    JOIN RiskLevels r ON a.level_id = r.level_id 
                    ORDER BY a.created_at DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>Security Alerts</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Alerts</h2>
                        <button onclick="openModal('addAlertModal')" class="btn btn-primary btn-sm">+ Create Alert</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Alert ID</th>
                                <th>User</th>
                                <th>Alert Type</th>
                                <th>Message</th>
                                <th>Risk Level</th>
                                <th>Status</th>
                                <th>Created At</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($alerts as $alert): ?>
                            <tr>
                                <td>#<?php echo $alert['alert_id']; ?></td>
                                <td><?php echo htmlspecialchars($alert['full_name']); ?><br><small><?php echo htmlspecialchars($alert['username']); ?></small></td>
                                <td><?php echo htmlspecialchars($alert['alert_type']); ?></td>
                                <td><?php echo htmlspecialchars($alert['alert_message']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($alert['level_name']); ?>"><?php echo $alert['level_name']; ?></span></td>
                                <td><span class="badge badge-<?php echo strtolower($alert['status']); ?>"><?php echo $alert['status']; ?></span></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($alert['created_at'])); ?></td>
                                <td>
                                    <select onchange="updateAlertStatus(<?php echo $alert['alert_id']; ?>, this.value)" class="form-control" style="width: auto; display: inline-block;">
                                        <option value="">Change Status</option>
                                        <option value="Open">Open</option>
                                        <option value="Investigating">Investigating</option>
                                        <option value="Closed">Closed</option>
                                    </select>
                                    <?php if ($alert['status'] != 'Closed'): ?>
                                    <button onclick="startInvestigation(<?php echo $alert['alert_id']; ?>)" class="btn btn-primary btn-sm">Investigate</button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'investigations') {
                $investigations = $pdo->query("
                    SELECT i.*, a.alert_type, a.alert_message, u.username, u.full_name 
                    FROM Investigations i 
                    JOIN Alerts a ON i.alert_id = a.alert_id 
                    JOIN Users u ON a.user_id = u.user_id 
                    ORDER BY i.started_at DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>Investigations</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Investigations</h2>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Alert</th>
                                <th>User</th>
                                <th>Investigator</th>
                                <th>Status</th>
                                <th>Findings</th>
                                <th>Started</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($investigations as $inv): ?>
                            <tr>
                                <td>#<?php echo $inv['investigation_id']; ?></td>
                                <td><?php echo htmlspecialchars($inv['alert_type']); ?></td>
                                <td><?php echo htmlspecialchars($inv['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($inv['investigator_name']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower(str_replace(' ', '', $inv['investigation_status'])); ?>"><?php echo $inv['investigation_status']; ?></span></td>
                                <td><?php echo htmlspecialchars(substr($inv['findings'], 0, 50)); ?><?php echo strlen($inv['findings']) > 50 ? '...' : ''; ?></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($inv['started_at'])); ?></td>
                                <td>
                                    <button
                                        class="btn btn-warning btn-sm update-investigation-btn"
                                        data-id="<?php echo (int)$inv['investigation_id']; ?>"
                                        data-status="<?php echo htmlspecialchars($inv['investigation_status']); ?>"
                                        data-findings="<?php echo htmlspecialchars($inv['findings'], ENT_QUOTES); ?>">
                                        Update
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'suspicious') {
                $actions = $pdo->query("
                    SELECT sa.*, u.username, u.full_name, d.hostname 
                    FROM SuspiciousActions sa 
                    JOIN Users u ON sa.user_id = u.user_id 
                    JOIN Devices d ON sa.device_id = d.device_id 
                    ORDER BY sa.timestamp DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>Suspicious Actions</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Suspicious Activities</h2>
                        <button onclick="openModal('addSuspiciousModal')" class="btn btn-primary btn-sm">+ Log Suspicious Action</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Action ID</th>
                                <th>User</th>
                                <th>Device</th>
                                <th>Action Type</th>
                                <th>Description</th>
                                <th>Source</th>
                                <th>Severity</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($actions as $action): ?>
                            <tr>
                                <td>#<?php echo $action['action_id']; ?></td>
                                <td><?php echo htmlspecialchars($action['full_name']); ?><br><small><?php echo htmlspecialchars($action['username']); ?></small></td>
                                <td><?php echo htmlspecialchars($action['hostname']); ?></td>
                                <td><?php echo htmlspecialchars($action['action_type']); ?></td>
                                <td><?php echo htmlspecialchars($action['action_description']); ?></td>
                                <td><?php echo htmlspecialchars($action['raw_source']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($action['severity']); ?>"><?php echo $action['severity']; ?></span></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($action['timestamp'])); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'devices') {
                $devices = $pdo->query("
                    SELECT d.*, u.username, u.full_name 
                    FROM Devices d 
                    JOIN Users u ON d.user_id = u.user_id 
                    ORDER BY d.registered_at DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>Registered Devices</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Devices</h2>
                        <button onclick="openModal('addDeviceModal')" class="btn btn-primary btn-sm">+ Register Device</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Device ID</th>
                                <th>User</th>
                                <th>Hostname</th>
                                <th>IP Address</th>
                                <th>Operating System</th>
                                <th>Status</th>
                                <th>Registered</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                            <tr>
                                <td><?php echo $device['device_id']; ?></td>
                                <td><?php echo htmlspecialchars($device['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($device['hostname']); ?></td>
                                <td><?php echo htmlspecialchars($device['ip_address']); ?></td>
                                <td><?php echo htmlspecialchars($device['os']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($device['status']); ?>"><?php echo $device['status']; ?></span></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($device['registered_at'])); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'logins') {
                $logins = $pdo->query("
                    SELECT lh.*, u.username, u.full_name, d.hostname 
                    FROM LoginHistory lh 
                    JOIN Users u ON lh.user_id = u.user_id 
                    JOIN Devices d ON lh.device_id = d.device_id 
                    ORDER BY lh.login_time DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>Login History</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All Login Records</h2>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Login ID</th>
                                <th>User</th>
                                <th>Device</th>
                                <th>Login Time</th>
                                <th>Logout Time</th>
                                <th>Location</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logins as $login): ?>
                            <tr>
                                <td>#<?php echo $login['login_id']; ?></td>
                                <td><?php echo htmlspecialchars($login['full_name']); ?><br><small><?php echo htmlspecialchars($login['username']); ?></small></td>
                                <td><?php echo htmlspecialchars($login['hostname']); ?></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($login['login_time'])); ?></td>
                                <td><?php echo $login['logout_time'] ? date('Y-m-d H:i', strtotime($login['logout_time'])) : 'Active'; ?></td>
                                <td><?php echo htmlspecialchars($login['location']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($login['login_status']); ?>"><?php echo $login['login_status']; ?></span></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            <?php } elseif ($page == 'files') {
                $files = $pdo->query("
                    SELECT fa.*, u.username, u.full_name, d.hostname 
                    FROM FileAccessLogs fa 
                    JOIN Users u ON fa.user_id = u.user_id 
                    JOIN Devices d ON fa.device_id = d.device_id 
                    ORDER BY fa.timestamp DESC
                ")->fetchAll(PDO::FETCH_ASSOC);
                ?>

                <div class="header">
                    <h1>File Access Logs</h1>
                </div>

                <div class="table-container">
                    <div class="table-header">
                        <h2>All File Access Records</h2>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Access ID</th>
                                <th>User</th>
                                <th>Device</th>
                                <th>File Path</th>
                                <th>Action</th>
                                <th>Sensitivity</th>
                                <th>Status</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($files as $file): ?>
                            <tr>
                                <td>#<?php echo $file['access_id']; ?></td>
                                <td><?php echo htmlspecialchars($file['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($file['hostname']); ?></td>
                                <td><code><?php echo htmlspecialchars($file['file_path']); ?></code></td>
                                <td><?php echo htmlspecialchars($file['action']); ?></td>
                                <td><span class="badge badge-<?php echo strtolower($file['sensitivity_level']); ?>"><?php echo $file['sensitivity_level']; ?></span></td>
                                <td><span class="badge badge-<?php echo strtolower($file['status']); ?>"><?php echo $file['status']; ?></span></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($file['timestamp'])); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php } ?>
        </main>
    </div>

    <!-- Modals -->
    <!-- Add User Modal -->
    <div id="addUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Add New User</h2>
                <button class="close-modal" onclick="closeModal('addUserModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="full_name" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <input type="text" name="role" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Department</label>
                        <input type="text" name="department" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" class="form-control" required minlength="8">
                    </div>
                    <div class="form-group">
                        <label>Privilege Level (1-5)</label>
                        <input type="number" name="privilege_level" class="form-control" min="1" max="5" required>
                    </div>
                </div>
                <button type="submit" name="add_user" class="btn btn-primary">Add User</button>
            </form>
        </div>
    </div>

    <!-- Add Alert Modal -->
    <div id="addAlertModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Create New Alert</h2>
                <button class="close-modal" onclick="closeModal('addAlertModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label>User</label>
                    <select name="user_id" class="form-control" required>
                        <option value="">Select User</option>
                        <?php
                        $users = $pdo->query("SELECT user_id, username, full_name FROM Users WHERE status='Active'")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($users as $user) {
                            echo "<option value='" . (int)$user['user_id'] . "'>" . htmlspecialchars($user['full_name']) . " (" . htmlspecialchars($user['username']) . ")</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Risk Level</label>
                    <select name="level_id" class="form-control" required>
                        <?php
                        $levels = $pdo->query("SELECT level_id, level_name FROM RiskLevels")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($levels as $level) {
                            echo "<option value='" . (int)$level['level_id'] . "'>" . htmlspecialchars($level['level_name']) . "</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Alert Type</label>
                    <input type="text" name="alert_type" class="form-control" placeholder="e.g., Suspicious File Access" required>
                </div>
                <div class="form-group">
                    <label>Alert Message</label>
                    <textarea name="alert_message" class="form-control" required></textarea>
                </div>
                <button type="submit" name="add_alert" class="btn btn-primary">Create Alert</button>
            </form>
        </div>
    </div>

    <!-- Start Investigation Modal -->
    <div id="startInvestigationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Start Investigation</h2>
                <button class="close-modal" onclick="closeModal('startInvestigationModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="alert_id" id="investigation_alert_id">
                <div class="form-group">
                    <label>Initial Findings</label>
                    <textarea name="findings" class="form-control" placeholder="Enter initial investigation findings..."></textarea>
                </div>
                <button type="submit" name="add_investigation" class="btn btn-primary">Start Investigation</button>
            </form>
        </div>
    </div>

    <!-- Update Investigation Modal -->
    <div id="updateInvestigationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Update Investigation</h2>
                <button class="close-modal" onclick="closeModal('updateInvestigationModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="investigation_id" id="update_investigation_id">
                <div class="form-group">
                    <label>Status</label>
                    <select name="investigation_status" class="form-control" required>
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Closed">Closed</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Findings</label>
                    <textarea name="findings" id="update_findings" class="form-control" required></textarea>
                </div>
                <button type="submit" name="update_investigation" class="btn btn-warning">Update Investigation</button>
            </form>
        </div>
    </div>

    <!-- Add Device Modal -->
    <div id="addDeviceModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Register New Device</h2>
                <button class="close-modal" onclick="closeModal('addDeviceModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label>User</label>
                    <select name="user_id" class="form-control" required>
                        <option value="">Select User</option>
                        <?php
                        $users = $pdo->query("SELECT user_id, username, full_name FROM Users WHERE status='Active'")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($users as $user) {
                            echo "<option value='" . (int)$user['user_id'] . "'>" . htmlspecialchars($user['full_name']) . " (" . htmlspecialchars($user['username']) . ")</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Hostname</label>
                    <input type="text" name="hostname" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>IP Address</label>
                    <input type="text" name="ip_address" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Operating System</label>
                    <input type="text" name="os" class="form-control" required>
                </div>
                <button type="submit" name="add_device" class="btn btn-primary">Register Device</button>
            </form>
        </div>
    </div>

    <!-- Add Suspicious Action Modal -->
    <div id="addSuspiciousModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Log Suspicious Action</h2>
                <button class="close-modal" onclick="closeModal('addSuspiciousModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label>User</label>
                    <select name="user_id" class="form-control" required>
                        <option value="">Select User</option>
                        <?php
                        $users = $pdo->query("SELECT user_id, username, full_name FROM Users WHERE status='Active'")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($users as $user) {
                            echo "<option value='" . (int)$user['user_id'] . "'>" . htmlspecialchars($user['full_name']) . " (" . htmlspecialchars($user['username']) . ")</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Device</label>
                    <select name="device_id" class="form-control" required>
                        <option value="">Select Device</option>
                        <?php
                        $devices = $pdo->query("SELECT device_id, hostname FROM Devices WHERE status='Active'")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($devices as $device) {
                            echo "<option value='" . (int)$device['device_id'] . "'>" . htmlspecialchars($device['hostname']) . "</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Action Type</label>
                    <input type="text" name="action_type" class="form-control" placeholder="e.g., USB_Insert, Mass_Download" required>
                </div>
                <div class="form-group">
                    <label>Source</label>
                    <select name="raw_source" class="form-control" required>
                        <option value="LoginHistory">Login History</option>
                        <option value="FileAccessLogs">File Access Logs</option>
                        <option value="DeviceEvents">Device Events</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="action_description" class="form-control" required></textarea>
                </div>
                <div class="form-group">
                    <label>Severity</label>
                    <select name="severity" class="form-control" required>
                        <option value="Low">Low</option>
                        <option value="Medium">Medium</option>
                        <option value="High">High</option>
                        <option value="Critical">Critical</option>
                    </select>
                </div>
                <button type="submit" name="add_suspicious" class="btn btn-primary">Log Action</button>
            </form>
        </div>
    </div>

    <!-- Update Behavior Score Modal -->
    <div id="updateScoreModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Update User Risk Score</h2>
                <button class="close-modal" onclick="closeModal('updateScoreModal')">&times;</button>
            </div>
            <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label>User</label>
                    <select name="user_id" class="form-control" required>
                        <option value="">Select User</option>
                        <?php
                        $users = $pdo->query("SELECT user_id, username, full_name FROM Users WHERE status='Active'")->fetchAll(PDO::FETCH_ASSOC);
                        foreach ($users as $user) {
                            echo "<option value='" . (int)$user['user_id'] . "'>" . htmlspecialchars($user['full_name']) . " (" . htmlspecialchars($user['username']) . ")</option>";
                        }
                        ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Login Anomaly Score</label>
                    <input type="number" name="login_anomaly_score" class="form-control" min="0" required>
                </div>
                <div class="form-group">
                    <label>File Access Score</label>
                    <input type="number" name="file_access_score" class="form-control" min="0" required>
                </div>
                <div class="form-group">
                    <label>Device Score</label>
                    <input type="number" name="device_score" class="form-control" min="0" required>
                </div>
                <button type="submit" name="update_behavior_score" class="btn btn-warning">Update Score</button>
            </form>
        </div>
    </div>

    <!-- Change User Status Form (Hidden) -->
    <form id="changeStatusForm" method="POST" style="display:none;">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="user_id" id="change_status_user_id">
        <input type="hidden" name="status" id="change_status_value">
        <input type="hidden" name="update_user_status" value="1">
    </form>

    <!-- Update Alert Status Form (Hidden) -->
    <form id="updateAlertForm" method="POST" style="display:none;">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="alert_id" id="update_alert_id">
        <input type="hidden" name="status" id="update_alert_status">
        <input type="hidden" name="update_alert_status" value="1">
    </form>

    <script>
        function openModal(modalId) {
            document.getElementById(modalId).classList.add('active');
        }

        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }

        function changeUserStatus(userId, currentStatus) {
            const newStatus = currentStatus === 'Active' ? 'Disabled' : 'Active';
            if (confirm('Are you sure you want to change this user status to ' + newStatus + '?')) {
                document.getElementById('change_status_user_id').value = userId;
                document.getElementById('change_status_value').value = newStatus;
                document.getElementById('changeStatusForm').submit();
            }
        }

        function updateAlertStatus(alertId, newStatus) {
            if (newStatus && confirm('Change alert status to ' + newStatus + '?')) {
                document.getElementById('update_alert_id').value = alertId;
                document.getElementById('update_alert_status').value = newStatus;
                document.getElementById('updateAlertForm').submit();
            }
        }

        function startInvestigation(alertId) {
            document.getElementById('investigation_alert_id').value = alertId;
            openModal('startInvestigationModal');
        }

        function updateInvestigation(investigationId, findings, status) {
            document.getElementById('update_investigation_id').value = investigationId;
            document.getElementById('update_findings').value = findings;
            document.querySelector('#updateInvestigationModal select[name="investigation_status"]').value = status;
            openModal('updateInvestigationModal');
        }

        // Wire up Update buttons via data-* attributes instead of inline onclick
        // (avoids injecting free-text "findings" content directly into a JS string)
        document.querySelectorAll('.update-investigation-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                updateInvestigation(btn.dataset.id, btn.dataset.findings, btn.dataset.status);
            });
        });

        // Close modal when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.classList.remove('active');
            }
        }
    </script>
</body>
</html>