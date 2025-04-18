<?php
// OneImgBed图床系统 
//https://github.com/Rao-Ruixian/OneImgBed/

// ==================== 配置区域 ====================
define('UPLOAD_DIR', 'p');              // 上传目录
define('PASSWORD_HASH', '这里填写输出的hash值'); // 登录密码：使用password_hash('your_password', PASSWORD_BCRYPT)生成的哈希
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 最大文件大小 20MB
define('MAX_TOTAL_SIZE', 100 * 1024 * 1024); // 多文件上传最大总大小 100MB
define('ALLOWED_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']); // 允许的文件类型
define('SESSION_NAME', 'picbed_sess');  // Session名称
define('SESSION_LIFETIME', 3600);       // Session有效期(秒)
define('REQUIRE_HTTPS', true);          // 强制HTTPS
define('MAX_LOGIN_ATTEMPTS', 5);        // 最大登录尝试次数
define('LOGIN_BAN_TIME', 300);          // 登录失败锁定时间(秒)
define('BAN_LIST_FILE', 'ip_ban_list.txt'); // IP封禁列表文件
define('CSRF_TOKEN_EXPIRE', 1800);      // CSRF令牌有效期(秒)

// ==================== 初始化 ====================
session_name(SESSION_NAME);
session_set_cookie_params([
    'lifetime' => SESSION_LIFETIME,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => REQUIRE_HTTPS,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

// 强制HTTPS
if (REQUIRE_HTTPS && (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on')) {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

// 自动创建上传目录
if (!file_exists(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
    file_put_contents(UPLOAD_DIR . '/.htaccess', "Deny from all");
}

// 获取客户端真实IP
function getClientIP()
{
    $ip = $_SERVER['REMOTE_ADDR'];
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ipList[0]);
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
}

$clientIP = getClientIP();

// ==================== IP封禁系统 ====================
function isIPBanned($ip)
{
    if (!file_exists(BAN_LIST_FILE)) return false;

    $banList = file(BAN_LIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($banList as $line) {
        $parts = explode('|', trim($line));
        if (count($parts) === 2) {
            list($bannedIP, $bannedUntil) = $parts;
            if ($bannedIP === $ip && time() < (int)$bannedUntil) {
                return true;
            }
        }
    }
    return false;
}

function banIP($ip, $duration = LOGIN_BAN_TIME)
{
    $banUntil = time() + $duration;
    $banEntry = "$ip|$banUntil" . PHP_EOL;
    file_put_contents(BAN_LIST_FILE, $banEntry, FILE_APPEND | LOCK_EX);
}

function cleanExpiredBans()
{
    if (!file_exists(BAN_LIST_FILE)) return;

    $banList = file(BAN_LIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $currentTime = time();
    $newList = [];

    foreach ($banList as $line) {
        $parts = explode('|', trim($line));
        if (count($parts) === 2) {
            list($bannedIP, $bannedUntil) = $parts;
            if ($currentTime < (int)$bannedUntil) {
                $newList[] = "$bannedIP|$bannedUntil";
            }
        }
    }

    file_put_contents(BAN_LIST_FILE, implode(PHP_EOL, $newList) . PHP_EOL, LOCK_EX);
}

// 清理过期的封禁记录
cleanExpiredBans();

// ==================== 安全函数 ====================
function sanitizeFilename($filename)
{
    $filename = preg_replace("/[^a-zA-Z0-9\.\-_]/", "", $filename);
    return substr($filename, 0, 100);
}

function isImage($filepath)
{
    $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $ext = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));
    return in_array($ext, $allowed);
}

function generateRandomName($length = 16)
{
    return bin2hex(random_bytes($length / 2));
}

function verifyImage($tmp_path)
{
    if (!getimagesize($tmp_path)) return false;
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    return in_array($finfo->file($tmp_path), ALLOWED_TYPES);
}

function getBaseUrl()
{
    $protocol = REQUIRE_HTTPS ? 'https://' : 'http://';
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    return $protocol . $_SERVER['HTTP_HOST'] . $path;
}

// ==================== CSRF 防护 ====================
function generateCSRFToken()
{
    if (
        empty($_SESSION['csrf_token']) ||
        (isset($_SESSION['csrf_token_time']) && (time() - $_SESSION['csrf_token_time']) > CSRF_TOKEN_EXPIRE)
    ) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token)
{
    if (empty($token)) return false;
    if (empty($_SESSION['csrf_token'])) return false;
    if (empty($_SESSION['csrf_token_time'])) return false;
    if ((time() - $_SESSION['csrf_token_time']) > CSRF_TOKEN_EXPIRE) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}

// ==================== 认证检查 ====================
function isLoggedIn()
{
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

function logout()
{
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ==================== 文件操作 ====================
function handleUpload()
{
    if (!isset($_FILES['images']) || empty($_FILES['images']['name'][0])) {
        return ['success' => false, 'message' => '请选择至少一个文件'];
    }

    $files = $_FILES['images'];
    $uploadedFiles = [];
    $totalSize = 0;

    // 检查总大小
    foreach ($files['size'] as $size) {
        $totalSize += $size;
    }

    if ($totalSize > MAX_TOTAL_SIZE) {
        return ['success' => false, 'message' => '文件总大小超过限制 (最大 ' . (MAX_TOTAL_SIZE / 1024 / 1024) . 'MB)'];
    }

    // 处理每个文件
    foreach ($files['name'] as $i => $name) {
        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            continue;
        }

        if ($files['size'][$i] > MAX_FILE_SIZE) {
            continue;
        }

        if (!verifyImage($files['tmp_name'][$i])) {
            continue;
        }

        // 检查文件内容是否真的是图片
        $imageInfo = getimagesize($files['tmp_name'][$i]);
        if (!$imageInfo || !in_array($imageInfo['mime'], ALLOWED_TYPES)) {
            continue;
        }

        // 检查文件扩展名是否匹配内容类型
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        $validExts = [
            'image/jpeg' => ['jpg', 'jpeg'],
            'image/png' => ['png'],
            'image/gif' => ['gif'],
            'image/webp' => ['webp']
        ];

        if (!in_array($ext, $validExts[$imageInfo['mime']])) {
            continue;
        }

        // 生成安全文件名
        $filename = generateRandomName() . '.' . $ext;
        $destination = UPLOAD_DIR . '/' . $filename;

        // 移动文件
        if (move_uploaded_file($files['tmp_name'][$i], $destination)) {
            // 二次验证文件内容
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime = $finfo->file($destination);
            if (!in_array($mime, ALLOWED_TYPES)) {
                unlink($destination);
                continue;
            }

            $uploadedFiles[] = $filename;
        }
    }

    if (empty($uploadedFiles)) {
        return ['success' => false, 'message' => '没有文件上传成功，请检查文件格式和大小'];
    }

    return ['success' => true, 'files' => $uploadedFiles];
}

// 处理粘贴上传
function handlePasteUpload($base64Data)
{
    // 检查base64数据格式
    if (!preg_match('/^data:image\/(\w+);base64,/', $base64Data, $matches)) {
        return ['success' => false, 'message' => '无效的图片数据'];
    }

    $imageType = strtolower($matches[1]);
    if (!in_array("image/$imageType", ALLOWED_TYPES)) {
        return ['success' => false, 'message' => '不允许的图片类型'];
    }

    // 移除base64头部
    $base64Data = str_replace($matches[0], '', $base64Data);
    $base64Data = str_replace(' ', '+', $base64Data);
    $imageData = base64_decode($base64Data);

    // 检查解码是否成功
    if ($imageData === false) {
        return ['success' => false, 'message' => '图片解码失败'];
    }

    // 检查图片大小
    if (strlen($imageData) > MAX_FILE_SIZE) {
        return ['success' => false, 'message' => '图片大小超过限制'];
    }

    // 保存临时文件并验证
    $tmpPath = tempnam(sys_get_temp_dir(), 'paste');
    file_put_contents($tmpPath, $imageData);

    if (!verifyImage($tmpPath)) {
        unlink($tmpPath);
        return ['success' => false, 'message' => '无效的图片文件'];
    }

    // 生成文件名并保存
    $filename = generateRandomName() . '.' . $imageType;
    $destination = UPLOAD_DIR . '/' . $filename;

    if (file_put_contents($destination, $imageData)) {
        return ['success' => true, 'file' => $filename];
    } else {
        return ['success' => false, 'message' => '保存图片失败'];
    }
}

function deleteImage($filename)
{
    $filepath = UPLOAD_DIR . '/' . sanitizeFilename($filename);
    if (file_exists($filepath)) {  // 这里添加了缺少的右括号
        // 检查文件是否真的是图片
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($filepath);
        if (!in_array($mime, ALLOWED_TYPES)) {
            return false;
        }
        return unlink($filepath);
    }
    return false;
}

function getImageList()
{
    $images = [];
    if ($handle = opendir(UPLOAD_DIR)) {
        while (false !== ($entry = readdir($handle))) {
            $filepath = UPLOAD_DIR . '/' . $entry;
            if ($entry != "." && $entry != "..") {
                // 验证文件类型
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime = $finfo->file($filepath);
                if (in_array($mime, ALLOWED_TYPES)) {
                    $images[] = [
                        'name' => $entry,
                        'size' => filesize($filepath),
                        'date' => date("Y-m-d H:i:s", filemtime($filepath)),
                        'url' => getBaseUrl() . '/' . UPLOAD_DIR . '/' . $entry
                    ];
                }
            }
        }
        closedir($handle);
    }
    usort($images, function ($a, $b) {
        return strtotime($b['date']) - strtotime($a['date']);
    });
    return $images;
}

// ==================== 处理请求 ====================
$message = '';
$action = $_GET['action'] ?? '';
$showLoginForm = true;

// 生成CSRF令牌
generateCSRFToken();

// 登出
if ($action === 'logout') {
    if (isset($_GET['csrf_token']) && validateCSRFToken($_GET['csrf_token'])) {
        logout();
    } else {
        $message = '无效的CSRF令牌';
    }
}

// 检查IP是否被封禁
if (isIPBanned($clientIP)) {
    $message = '您的IP已被暂时封禁，请稍后再试';
    $showLoginForm = false;
}

// 登录
if (isset($_POST['login']) && $showLoginForm) {
    if (password_verify($_POST['password'], PASSWORD_HASH)) {
        $_SESSION['logged_in'] = true;
        $_SESSION['last_activity'] = time();
        $_SESSION['login_attempts'] = 0;
        generateCSRFToken(); // 登录成功后生成新的CSRF令牌
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;

        if ($_SESSION['login_attempts'] >= MAX_LOGIN_ATTEMPTS) {
            banIP($clientIP);
            $message = '由于多次登录失败，您的IP已被暂时封禁';
            $showLoginForm = false;
        } else {
            $remaining_attempts = MAX_LOGIN_ATTEMPTS - $_SESSION['login_attempts'];
            $message = '密码错误，剩余尝试次数: ' . $remaining_attempts;
        }
    }
}

// 处理AJAX上传
if (
    isLoggedIn() && isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest'
) {
    if (isset($_FILES['images']) && !empty($_FILES['images']['name'][0])) {
        $result = handleUpload();
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }
}
// 上传
if (isLoggedIn() && isset($_POST['upload'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = 'CSRF验证失败';
    } else {
        $result = handleUpload();
        if ($result['success']) {
            $_SESSION['upload_success'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $message = $result['message'];
        }
    }
}

// 粘贴上传
if (isLoggedIn() && isset($_POST['paste_upload'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = 'CSRF验证失败';
    } elseif (!empty($_POST['image_data'])) {
        $result = handlePasteUpload($_POST['image_data']);
        if ($result['success']) {
            $_SESSION['upload_success'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $message = $result['message'];
        }
    } else {
        $message = '没有接收到图片数据';
    }
}

// 显示上传成功消息
if (isLoggedIn() && isset($_SESSION['upload_success'])) {
    unset($_SESSION['upload_success']);
    $message = '上传成功!';
}

// 删除 - 使用POST方法防止刷新重复删除
if (isLoggedIn() && isset($_POST['delete'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = 'CSRF验证失败';
    } else {
        if (isset($_POST['file']) && deleteImage($_POST['file'])) {
            $_SESSION['delete_success'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $message = '删除失败';
        }
    }
}

// 显示删除成功消息
if (isLoggedIn() && isset($_SESSION['delete_success'])) {
    unset($_SESSION['delete_success']);
    $message = '文件已删除';
}

// 检查会话超时
if (isLoggedIn() && (time() - $_SESSION['last_activity']) > SESSION_LIFETIME) {
    logout();
}
$_SESSION['last_activity'] = time();

// ==================== HTML 输出 ====================
?>
<!DOCTYPE html>
<html lang="zh-CN">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:">
    <title>OneImgBed图床系统</title>
    <style>
        :root {
            --primary: #4a6fa5;
            --primary-light: #6b8cae;
            --primary-dark: #2c4a76;
            --secondary: #6c757d;
            --light: #f8f9fa;
            --dark: #343a40;
            --danger: #dc3545;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --white: #ffffff;
            --gray: #6c757d;
            --gray-light: #e9ecef;
            --border-radius: 0.375rem;
            --box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            --transition: all 0.3s ease;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background-color: #f5f7fa;
            color: var(--dark);
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px;
            background: var(--white);
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            position: relative;
        }

        h1,
        h2 {
            color: var(--primary);
            margin-bottom: 20px;
            text-align: center;
            font-weight: 600;
        }

        h1 {
            font-size: 2.2rem;
        }

        h2 {
            font-size: 1.8rem;
            margin-top: 40px;
        }

        .message {
            padding: 15px;
            margin-bottom: 25px;
            border-radius: var(--border-radius);
            text-align: center;
            font-weight: 500;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }

        .success {
            background-color: rgba(40, 167, 69, 0.1);
            color: var(--success);
            border: 1px solid rgba(40, 167, 69, 0.3);
        }

        .error {
            background-color: rgba(220, 53, 69, 0.1);
            color: var(--danger);
            border: 1px solid rgba(220, 53, 69, 0.3);
        }

        .warning {
            background-color: rgba(255, 193, 7, 0.1);
            color: #856404;
            border: 1px solid rgba(255, 193, 7, 0.3);
        }

        .login-form,
        .upload-form {
            max-width: 500px;
            margin: 0 auto 30px;
            padding: 30px;
            background: var(--light);
            border-radius: var(--border-radius);
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            transition: var(--transition);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark);
        }

        input[type="password"],
        input[type="file"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--gray-light);
            border-radius: var(--border-radius);
            font-size: 16px;
            transition: var(--transition);
        }

        input[type="password"]:focus,
        input[type="file"]:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 0.2rem rgba(74, 111, 165, 0.25);
        }

        .btn {
            display: inline-block;
            padding: 12px 24px;
            background-color: var(--primary);
            color: var(--white);
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            text-decoration: none;
            font-size: 16px;
            font-weight: 500;
            transition: var(--transition);
            text-align: center;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .btn:active {
            transform: translateY(0);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .btn-block {
            display: block;
            width: 100%;
        }

        .btn-danger {
            background-color: var(--danger);
        }

        .btn-danger:hover {
            background-color: #c82333;
        }

        .btn-info {
            background-color: var(--info);
        }

        .btn-info:hover {
            background-color: #138496;
        }

        .btn-warning {
            background-color: var(--warning);
            color: var(--dark);
        }

        .btn-warning:hover {
            background-color: #e0a800;
        }

        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }

        .image-card {
            border: 1px solid var(--gray-light);
            border-radius: var(--border-radius);
            overflow: hidden;
            transition: var(--transition);
            background: var(--white);
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }

        .image-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }

        .image-preview {
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-bottom: 1px solid var(--gray-light);
        }

        .image-info {
            padding: 20px;
        }

        .image-name {
            font-weight: 600;
            margin-bottom: 10px;
            word-break: break-all;
            color: var(--dark);
        }

        .image-meta {
            font-size: 14px;
            color: var(--gray);
            margin-bottom: 15px;
            line-height: 1.5;
        }

        .image-actions {
            display: flex;
            justify-content: space-between;
            gap: 10px;
        }

        .logout-link {
            display: inline-block;
            text-align: right;
            margin-bottom: 20px;
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
            float: right;
            padding: 8px 15px;
            border-radius: var(--border-radius);
        }

        .logout-link:hover {
            text-decoration: none;
            background-color: rgba(74, 111, 165, 0.1);
        }

        .url-box {
            width: 100%;
            padding: 10px;
            border: 1px solid var(--gray-light);
            border-radius: var(--border-radius);
            background: var(--light);
            font-size: 14px;
            margin-bottom: 15px;
            cursor: pointer;
            transition: var(--transition);
            font-family: monospace;
        }

        .url-box:hover {
            background: var(--gray-light);
        }

        .url-box:focus {
            outline: none;
            border-color: var(--primary);
        }

        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            background-color: rgba(51, 51, 51, 0.9);
            color: white;
            padding: 15px 30px;
            border-radius: var(--border-radius);
            z-index: 1000;
            opacity: 0;
            transition: opacity 0.3s ease, transform 0.3s ease;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            pointer-events: none;
        }

        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(-10px);
        }

        .upload-status {
            margin-top: 10px;
            font-size: 14px;
            color: var(--gray);
            font-style: italic;
        }

        /* 上传区域样式 */
        .upload-zone {
            border: 2px dashed var(--gray-light);
            border-radius: var(--border-radius);
            padding: 40px;
            text-align: center;
            margin-bottom: 25px;
            transition: var(--transition);
            background-color: rgba(248, 249, 250, 0.5);
            position: relative;
        }

        .upload-zone.highlight {
            border-color: var(--primary);
            background-color: rgba(74, 111, 165, 0.1);
        }

        .upload-zone-content {
            pointer-events: none;
        }

        .upload-zone-icon {
            font-size: 48px;
            color: var(--primary-light);
            margin-bottom: 15px;
        }

        .upload-zone-title {
            font-size: 18px;
            font-weight: 500;
            margin-bottom: 10px;
            color: var(--dark);
        }

        .upload-zone-desc {
            font-size: 14px;
            color: var(--gray);
            margin-bottom: 15px;
        }

        .upload-zone-hint {
            font-size: 12px;
            color: var(--gray);
            font-style: italic;
        }

        .file-input-wrapper {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }

        /* 上传进度条样式 */
        .progress-container {
            width: 100%;
            background-color: var(--gray-light);
            border-radius: var(--border-radius);
            margin: 15px 0;
            display: none;
        }

        .progress-bar {
            height: 20px;
            background-color: var(--primary);
            border-radius: var(--border-radius);
            width: 0%;
            transition: width 0.3s ease;
            text-align: center;
            color: white;
            font-size: 12px;
            line-height: 20px;
        }

        /* 加载动画 */
        .loader {
            display: none;
            width: 50px;
            height: 50px;
            margin: 20px auto;
            border: 5px solid var(--gray-light);
            border-radius: 50%;
            border-top: 5px solid var(--primary);
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% {
                transform: rotate(0deg);
            }

            100% {
                transform: rotate(360deg);
            }
        }

        /* 文件预览 */
        .file-preview-container {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }

        .file-preview {
            position: relative;
            width: 80px;
            height: 80px;
            border-radius: var(--border-radius);
            overflow: hidden;
            border: 1px solid var(--gray-light);
        }

        .file-preview img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .file-preview-remove {
            position: absolute;
            top: 5px;
            right: 5px;
            background-color: var(--danger);
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .file-preview:hover .file-preview-remove {
            opacity: 1;
        }

        .clearfix::after {
            content: "";
            display: table;
            clear: both;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }

            h1 {
                font-size: 1.8rem;
            }

            h2 {
                font-size: 1.5rem;
            }

            .login-form,
            .upload-form {
                padding: 20px;
            }

            .gallery {
                grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 15px;
            }

            .upload-zone {
                padding: 30px 20px;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 10px;
            }

            .container {
                padding: 15px;
            }

            .gallery {
                grid-template-columns: 1fr;
            }

            .image-actions {
                flex-direction: column;
            }

            .btn {
                width: 100%;
                margin-bottom: 10px;
            }
        }
    </style>
</head>

<body>
    <div class="container">
        <?php if (!isLoggedIn()): ?>
            <!-- 登录表单 -->
            <h1>图床系统登录</h1>

            <?php if ($message): ?>
                <div class="message <?php
                                    echo strpos($message, 'IP已被封禁') !== false ? 'error' : (strpos($message, '密码错误') !== false ? 'warning' : 'error');
                                    ?>">
                    <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <?php if ($showLoginForm): ?>
                <form class="login-form" method="post">
                    <div class="form-group">
                        <label for="password">密码</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" name="login" class="btn btn-block">登录</button>
                </form>
            <?php endif; ?>

        <?php else: ?>
            <!-- 已登录状态 -->
            <div class="clearfix">
                <a href="?action=logout&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="logout-link">退出登录</a>
            </div>
            <h1>OneImgBed图床管理系统</h1>

            <?php if ($message): ?>
                <div class="message <?php echo strpos($message, '成功') !== false ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <!-- 统一上传表单 -->
            <form class="upload-form" method="post" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <!-- 上传区域 - 支持拖拽和粘贴 -->
                <div class="upload-zone" id="uploadZone">
                    <div class="upload-zone-content">
                        <div class="upload-zone-icon">📁</div>
                        <div class="upload-zone-title">拖拽图片到此处 或 Ctrl+V粘贴剪贴板图片</div>
                        <div class="upload-zone-desc">支持JPG、PNG、GIF、WEBP格式，单文件最大<?php echo (MAX_FILE_SIZE / 1024 / 1024); ?>MB</div>
                        <div class="upload-zone-hint">也可以点击此处选择文件</div>
                    </div>
                    <input type="file" id="images" name="images[]" class="file-input-wrapper" accept="image/*" multiple>
                </div>

                <!-- 文件预览区域 -->
                <div class="file-preview-container" id="filePreview"></div>

                <!-- 上传进度条 -->
                <div class="progress-container" id="progressContainer">
                    <div class="progress-bar" id="progressBar">0%</div>
                </div>

                <!-- 加载动画 -->
                <div class="loader" id="loader"></div>

                <button type="submit" name="upload" class="btn btn-block" id="uploadBtn">上传图片</button>
            </form>

            <!-- 隐藏的粘贴表单 -->
            <form id="pasteForm" method="post" style="display:none;">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="image_data" id="imageData">
                <input type="hidden" name="paste_upload">
            </form>

            <!-- 图片列表 -->
            <h2>图片列表</h2>
            <?php $images = getImageList(); ?>

            <?php if (empty($images)): ?>
                <p style="text-align: center; color: var(--gray);">暂无图片</p>
            <?php else: ?>
                <div class="gallery">
                    <?php foreach ($images as $image): ?>
                        <div class="image-card">
                            <img src="<?php echo htmlspecialchars($image['url'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($image['name'], ENT_QUOTES, 'UTF-8'); ?>" class="image-preview" loading="lazy">
                            <div class="image-info">
                                <div class="image-name"><?php echo htmlspecialchars($image['name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                <div class="image-meta">
                                    <?php echo round($image['size'] / 1024, 2); ?> KB<br>
                                    <?php echo $image['date']; ?>
                                </div>
                                <input type="text" class="url-box" value="<?php echo htmlspecialchars($image['url'], ENT_QUOTES, 'UTF-8'); ?>" readonly onclick="copyToClipboard(this.value)">
                                <div class="image-actions">
                                    <button class="btn btn-info" onclick="copyToClipboard('<?php echo htmlspecialchars($image['url'], ENT_QUOTES, 'UTF-8'); ?>')">复制链接</button>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="file" value="<?php echo htmlspecialchars($image['name'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <button type="submit" name="delete" class="btn btn-danger" onclick="return confirm('确定要删除这张图片吗？')">删除</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <div class="toast" id="toast">链接已复制</div>

    <script>
        // 复制到剪贴板
        function copyToClipboard(text) {
            const input = document.createElement('input');
            input.value = text;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);

            // 显示toast提示
            showToast('链接已复制');
        }

        // 显示提示
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
            }, 2000);
        }

        // 统一上传区域功能
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('images');
        const filePreview = document.getElementById('filePreview');
        const uploadForm = document.getElementById('uploadForm');
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('progressBar');
        const loader = document.getElementById('loader');
        const uploadBtn = document.getElementById('uploadBtn');

        // 拖拽功能
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => {
                uploadZone.classList.add('highlight');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => {
                uploadZone.classList.remove('highlight');
            });
        });

        uploadZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            fileInput.files = dt.files;
            // 显示文件预览
            showFilePreviews(dt.files);
        });

        // 文件选择变化时显示预览
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                showFilePreviews(this.files);
            }
        });

        // 显示文件预览
        function showFilePreviews(files) {
            filePreview.innerHTML = '';

            if (files.length > 0) {
                let filesInfo = '';
                if (files.length === 1) {
                    filesInfo = `已选择: ${files[0].name}`;
                } else {
                    filesInfo = `已选择 ${files.length} 个文件`;
                }
                showToast(filesInfo);

                // 显示预览
                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    if (!file.type.match('image.*')) continue;

                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const preview = document.createElement('div');
                        preview.className = 'file-preview';

                        const img = document.createElement('img');
                        img.src = e.target.result;

                        const removeBtn = document.createElement('div');
                        removeBtn.className = 'file-preview-remove';
                        removeBtn.innerHTML = '×';
                        removeBtn.onclick = function() {
                            preview.remove();
                            updateFileInput();
                        };

                        preview.appendChild(img);
                        preview.appendChild(removeBtn);
                        filePreview.appendChild(preview);
                    };
                    reader.readAsDataURL(file);
                }
            }
        }

        // 更新文件输入
        function updateFileInput() {
            const previews = filePreview.querySelectorAll('.file-preview');
            if (previews.length === 0) {
                fileInput.value = '';
                return;
            }

            // 创建一个新的DataTransfer对象来保存文件
            const dataTransfer = new DataTransfer();

            // 遍历所有预览，从原始文件列表中查找对应的文件
            for (let i = 0; i < fileInput.files.length; i++) {
                const file = fileInput.files[i];
                let fileExists = false;

                // 检查这个文件是否在预览中
                for (let j = 0; j < previews.length; j++) {
                    const preview = previews[j];
                    if (preview.querySelector('img').src.includes(file.name)) {
                        fileExists = true;
                        break;
                    }
                }

                if (fileExists) {
                    dataTransfer.items.add(file);
                }
            }

            // 更新文件输入
            fileInput.files = dataTransfer.files;
        }

        // 粘贴功能
        document.addEventListener('paste', async (e) => {
            // 只在焦点不在输入框时处理
            if (document.activeElement.tagName === 'INPUT') return;

            if (!e.clipboardData || !e.clipboardData.items) return;

            for (let i = 0; i < e.clipboardData.items.length; i++) {
                const item = e.clipboardData.items[i];
                if (item.type.indexOf('image') !== -1) {
                    const blob = item.getAsFile();
                    const reader = new FileReader();

                    reader.onload = function(e) {
                        document.getElementById('imageData').value = e.target.result;
                        // 显示粘贴提示
                        showToast('检测到剪贴板图片，正在上传...');
                        // 提交表单
                        document.getElementById('pasteForm').submit();
                    };

                    reader.readAsDataURL(blob);
                    break;
                }
            }
        });


        // AJAX上传表单
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();

            if (!fileInput.files || fileInput.files.length === 0) {
                showToast('请先选择文件');
                return;
            }

            // 显示加载状态
            uploadBtn.disabled = true;
            loader.style.display = 'block';
            progressContainer.style.display = 'block';

            try {
                const formData = new FormData(uploadForm);

                // 调试：检查FormData内容
                for (let [key, value] of formData.entries()) {
                    console.log(key, value);
                }

                const xhr = new XMLHttpRequest();
                xhr.open('POST', uploadForm.action || window.location.href, true);
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

                // 上传进度
                xhr.upload.onprogress = function(e) {
                    if (e.lengthComputable) {
                        const percent = Math.round((e.loaded / e.total) * 100);
                        progressBar.style.width = percent + '%';
                        progressBar.textContent = percent + '%';
                    }
                };

                xhr.onload = function() {
                    console.log('响应状态:', xhr.status);
                    console.log('响应内容:', xhr.responseText);

                    if (xhr.status === 200) {
                        try {
                            const response = JSON.parse(xhr.responseText);
                            if (response.success) {
                                showToast('上传成功!');
                                setTimeout(() => window.location.reload(), 1000);
                            } else {
                                showToast('上传失败: ' + (response.message || '未知错误'));
                            }
                        } catch (e) {
                            showToast('解析响应出错: ' + e.message);
                        }
                    } else {
                        showToast('服务器错误: ' + xhr.status);
                    }
                    resetUploadForm();
                };

                xhr.onerror = function() {
                    showToast('网络错误，请检查连接');
                    resetUploadForm();
                };

                xhr.ontimeout = function() {
                    showToast('请求超时');
                    resetUploadForm();
                };

                // 设置超时时间（毫秒）
                xhr.timeout = 60000;

                console.log('开始发送请求...');
                xhr.send(formData);

            } catch (error) {
                console.error('上传出错:', error);
                showToast('上传出错: ' + error.message);
                resetUploadForm();
            }
        });
    </script>
    <!-- 请遵守MIT开源协议，保留作者署名 -->
    <div style="text-align: center; margin-top: 30px; padding: 20px; color: var(--gray); font-size: 14px;">
        <p>OneImgBed图床 © 2025 由 <a href="https://blog.rrxweb.top/" target="_blank" style="color: var(--primary); text-decoration: none;">学游渊</a> 制作</p>
        <p>
            <a href="https://github.com/Rao-Ruixian/OneImgBed/" target="_blank" style="color: var(--primary); text-decoration: none;">
                <svg height="16" width="16" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 5px;">
                    <path fill-rule="evenodd" fill="var(--primary)" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
                GitHub 项目地址
            </a>
        </p>
    </div>
</body>

</html>