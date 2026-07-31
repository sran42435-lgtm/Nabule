<?php
// ========== KONEKSI DATABASE ==========
$host = "localhost";
$user = "root";
$pass = "";
$db = "testing_db";

$conn = mysqli_connect($host, $user, $pass, $db);

if (!$conn) {
    die("Koneksi gagal: " . mysqli_connect_error());
}

// ========== PROSES LOGIN (RENTAN SQL INJECTION) ==========
$login_status = "";
$login_message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // ⚠️ KERENTANAN: SQL Injection
    $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = mysqli_query($conn, $sql);
    
    if (mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);
        $login_status = "success";
        $login_message = "Selamat datang, " . $row['username'] . "! (Role: " . $row['role'] . ")";
    } else {
        $login_status = "failed";
        $login_message = "Username atau password salah!";
    }
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Admin - SQL Injection Test</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            padding: 40px;
            width: 100%;
            max-width: 450px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 5px;
        }
        
        .header .subtitle {
            color: #ff6b6b;
            font-size: 14px;
            background: #ffe6e6;
            padding: 5px 15px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 10px;
            font-weight: bold;
        }
        
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 13px;
            color: #856404;
        }
        
        .warning-box strong {
            display: block;
            margin-bottom: 5px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-weight: 600;
            color: #555;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 12px;
            font-size: 15px;
            transition: all 0.3s;
            background: #f8f9fa;
        }
        
        .form-group input:focus {
            border-color: #667eea;
            background: white;
            outline: none;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .status-message {
            margin-bottom: 20px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            font-weight: 600;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .footer {
            margin-top: 25px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
        
        .payload-examples {
            margin-top: 25px;
            padding: 15px;
            background: #f0f0f0;
            border-radius: 12px;
        }
        
        .payload-examples h4 {
            color: #555;
            margin-bottom: 10px;
            font-size: 14px;
        }
        
        .payload-examples code {
            display: block;
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 13px;
            word-break: break-all;
        }
        
        .payload-examples code span {
            color: #66d9ef;
        }
        
        .demo-cred {
            background: #e8f5e9;
            padding: 12px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 13px;
            color: #2e7d32;
        }
        
        .demo-cred code {
            background: #c8e6c9;
            padding: 2px 8px;
            border-radius: 4px;
        }
        
        .ip-info {
            background: #e3f2fd;
            padding: 10px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 13px;
            color: #0d47a1;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <h1>🔐 Admin Panel</h1>
            <span class="subtitle">⚠️ MODE TESTING - RENTAN SQL INJECTION</span>
        </div>
        
        <!-- WARNING -->
        <div class="warning-box">
            <strong>⚠️ PERINGATAN KEAMANAN:</strong>
            Website ini <strong>sengaja dibuat rentan</strong> terhadap SQL Injection 
            untuk tujuan <strong>testing keamanan di lingkungan LOKAL</strong>. 
            Jangan deploy ke server publik!
        </div>
        
        <!-- STATUS LOGIN -->
        <div class="status-message">
            <?php if ($_SERVER["REQUEST_METHOD"] == "POST"): ?>
                <div class="alert alert-<?php echo $login_status == 'success' ? 'success' : 'danger'; ?>">
                    <?php echo $login_message; ?>
                </div>
            <?php endif; ?>
        </div>
        
        <!-- FORM LOGIN -->
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">👤 Username</label>
                <input type="text" id="username" name="username" placeholder="Masukkan username" required>
            </div>
            
            <div class="form-group">
                <label for="password">🔑 Password</label>
                <input type="password" id="password" name="password" placeholder="Masukkan password" required>
            </div>
            
            <button type="submit" class="btn-login">Login</button>
        </form>
        
        <!-- DEMO CREDENTIALS -->
        <div class="demo-cred">
            <strong>📝 Data Demo:</strong><br>
            Username: <code>admin</code> | Password: <code>admin123</code>
        </div>
        
        <!-- PAYLOAD EXAMPLES -->
        <div class="payload-examples">
            <h4>⚡ Contoh Payload SQL Injection:</h4>
            <code><span>Username:</span> ' OR '1'='1' -- </code>
            <code><span>Username:</span> admin' -- </code>
            <code><span>Username:</span> ' UNION SELECT 1,2,3,4 -- </code>
        </div>
        
        <!-- IP INFO -->
        <div class="ip-info">
            🌐 Akses via: <strong><?php echo $_SERVER['SERVER_ADDR']; ?></strong> 
            (Port: <?php echo $_SERVER['SERVER_PORT']; ?>)
        </div>
        
        <div class="footer">
            <p>🔒 Untuk testing keamanan <strong>LOKAL</strong> saja | SQL Injection Demo v1.0</p>
        </div>
    </div>
</body>
</html>
