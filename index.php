<?php

declare(strict_types=1);

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// enforce httpS
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect);
    exit();
}

// configuration of script
define('PHP_DISABLE', false);
define('SESSION_TIMEOUT', 300); // 5 minutes
//define('BASE_DIR', '../data');
define('BASE_DIR', '/homepages/htdocs/files/data');
define('HASHED_PASSWORD', password_hash('password', PASSWORD_DEFAULT));

class DirectoryManager {
    private $csrfToken;
    private $hashedPassword = HASHED_PASSWORD;

    private $basePathAbs;
    private $currentPathRel;
    private $messages = [];
    
    private $isPublic = true;

    private $excludedExtensions = ['htaccess', 'php', 'phtml', 'phar'];

    public function __construct($basePath) {
        $this->basePathAbs = realpath($basePath); // ensure absolut path
        
        // session management
        $this->startSession();

        // authentication & security
        if (!$this->isAuthenticated()) {
            $this->renderLoginForm();
            exit();
        }
        
        $this->isPublic = false;

        // prepare safe "currentPathRel"
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $requestPath = $this->sanitizeRelPath($_POST['current_path'] ?? '/');
        } else {
            $requestPath = $this->sanitizeRelPath($_GET['p'] ?? '/');
        }
        if (!$requestPath) {
            $this->addMessages('Error', 'Invalid directory requested');
            $this->renderLoginForm();
            exit();
        }

        $this->currentPathRel = substr($requestPath, strlen($this->basePathAbs));
    }

    private function startSession() {
        // configure cookie safety
        session_set_cookie_params([
            'lifetime' => 0, // Session cookie (expires on browser close)
            'path' => '/', // Cookie available across the entire domain
            'domain' => $_SERVER['SERVER_NAME'],
            'secure' => true, // Only send cookie over HTTPS
            'httponly' => true, // Prevent JavaScript access
            'samesite' => 'Strict' // Mitigate CSRF (can also use 'Lax')
        ]);

        session_start();

        // verify timeout
        if (isset($_SESSION['last_activity'])) {
            $elapsed_time = time() - $_SESSION['last_activity'];
        
            if ($elapsed_time > SESSION_TIMEOUT) {
                // Timeout: Destroy the session and log the user out
                session_unset(); // Clear session variables
                session_destroy(); // Destroy the session
                header("Location: /"); // Redirect to login form
                exit();
            }
        }
        $_SESSION['last_activity'] = time();

        // set or create new CSRF Token
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        $this->csrfToken = $_SESSION['csrf_token'];
    }

    private function isValidCsrfToken($token) {
        return $token === $this->csrfToken;
    }

    private function isValidPassword($password) {
        if (!password_verify($password, $this->hashedPassword)) {
            $this->addMessages('Error', 'Incorrect password!');
            $this->renderLoginForm();
            exit();
        }

        $_SESSION['authenticated'] = true;
        session_regenerate_id(true);
        return true;
    }

    private function isAuthenticated() {
        if (isset($_SESSION['authenticated']) && $_SESSION['authenticated']) {
            return true;
        }

        // POST request with password AND CSRF-Token
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['csrf_token']) && $this->isValidCsrfToken($_POST['csrf_token'])) {
            if (isset($_POST['password']) && $this->isValidPassword($_POST['password'])) {
                return true;
            }

            // CSRF Token invalid or Password wrong
            return false;
        }
    
        // e.g. GET request || token invalid
        $this->addMessages('Error', 'Authentication required');
        return false;
    }

    private function sanitizeRelPath($path) {
        // Remove null bytes and any suspicious characters
        $path = preg_replace('/[\x00-\x1F\x7F]/', '', $path);
        $path = trim($path, "/");

        // Allow only specific patterns (e.g., alphanumeric, hyphens, underscores, slashes)
        if (!preg_match('#^[a-zA-Z0-9_\-/]+$#', $path)) {
            return '/';
        }

        // Resolve the full path
        $resolvedPath = realpath($this->basePathAbs . '/' . $path);

        // Ensure the resolved path is within the base directory
        if (!$resolvedPath || strpos($resolvedPath, $this->basePathAbs) !== 0) {
            return '/';
        }

        return $resolvedPath;
    }

    private function logout() {
        // Destroy session data
        session_unset();
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();

        $this->addMessages('Info', 'Logged out successfully.');

        // Regenerate session ID for safety
        session_start();
        session_regenerate_id(true);

        $this->renderLoginForm(false);
        exit();
    }

    private function addMessages($type, $message) {
        $this->messages[] = [
            'type' => $type,
            'message' => $message
        ];
    }

    private function printMessages() {
        foreach ($this->messages as $msg) {
            $typeClass = $msg['type'] === 'Error' ? 'error' : 'info';
            echo '<' . $typeClass . '>' .  htmlspecialchars($msg['message'], ENT_QUOTES, 'UTF-8') . '</' . $typeClass . '>';
        }
    }

    public function renderLoginForm(bool $delay = true) {
        $waitTime = runThrottle();
        if ($delay && $waitTime) {
            // raise efforts on Brute-Force attacs
            // sleep(1);
            $this->addMessages('Error', "To many Request. Wait for $waitTime seconds.");
        }
        echo '<!DOCTYPE html>';
        echo '<html>';
        echo '<head>';
        echo '<meta charset="UTF-8">';
        echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">';
        echo '<link rel="icon" type="image/svg+xml" href="svg/favicon.svg">';
        echo '<title>Login</title>';
        echo '<link rel="stylesheet" href="style.css">';
        echo '</head>';
        echo '<body>';
        echo '<nav>';
        $this->printMessages();
        echo '</nav>';
        echo '<h1>files</h1>';
        echo '<form class="formInline" action="/" method="POST">';
        echo '<div id="pwd">';
        echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
        echo '<input type="password" name="password" autofocus>';
        echo '<button type="submit" class="login">&nbsp;</button>';
        echo '</div>';
        echo '</form>';
        echo '</body>';
        echo '</html>';
    }

    private function verifyPath($path, $isFile = true) {
        // convert %20 to space, etc
        $path_decoded = urldecode($path);

        // Validate basic filename/path structure
        if (!$this->isValidPathComponent($path_decoded)) {
            return false;
        }

        // Construct the absolute path
        $fullPath = realpath($this->basePathAbs . $this->currentPathRel . '/' . $path_decoded);

        // Ensure the path resolves to a valid location within the base directory
        if (!$fullPath || strpos($fullPath, $this->basePathAbs) !== 0) {
            return false;
        }

        // Additional checks based on the type of operation
        if ($isFile) {
            // Ensure it's a valid file and not a symlink
            if (!is_file($fullPath) || is_link($fullPath)) {
                return false;
            }

        } else {
            // isDir
            // Ensure it's a valid directory and not a symlink
            if (!is_dir($fullPath) || is_link($fullPath)) {
                return false;
            }
        }

        return $fullPath;
    }

    private function verifyNewPath($path) {
        // convert %20 to space, etc
        $path_decoded = urldecode($path);

        // Validate basic filename/path structure
        if (!$this->isValidPathComponent($path_decoded)) {
            return false;
        }

        // Construct the absolute path
        $fullParentDir = realpath($this->basePathAbs . $this->currentPathRel);
        // Ensure the path resolves to a valid location within the base directory
        if (!$fullParentDir || strpos($fullParentDir, $this->basePathAbs) !== 0) {
            return false; // invalid base directory
        }
        
        $fullPath = $fullParentDir . '/' . $path_decoded;

        // Check if the path stays within the base directory
        if (strpos(realpath(dirname($fullPath)) ?: dirname($fullPath), $this->basePathAbs) !== 0) {
            return false; // Path escapes the base directory
        }

        // Additional checks based on the type of operation
        // Check if the parent directory is writable for file creation
        if (!is_writable($fullParentDir)) {
            return false;
        }
        
        return $fullPath;
    }

    // Helper function to validate filenames or path components
    private function isValidPathComponent($component) {
        $parts = explode('/', $component);

        foreach ($parts as $part) {
            // Avoid empty parts or dot-based tricks
            if ($part === '' || $part === '.' || $part === '..') {
                return false;
            }

            // Avoid hidden files (e.g. .htaccess)
            if (strpos($part, '.') === 0) {
                return false;
            }

            // Allowed characters: Latin letters, digits, German umlauts, ß, underscore, dash, dot, space, percent
            if (!preg_match('/^[a-zA-Z0-9äöüÄÖÜß_\-\. %]+$/u', $part)) {
                return false;
            }

            // Avoid dangerous Windows characters
            if (preg_match('/[<>:"|?*]/', $part)) {
                return false;
            }
        }

        return true;
    }

    public function handleRequest() {
        if (isset($_GET['logout'])) {
            $this->logout();

        } elseif (isset($_GET['v'])) {
            $filePath = $this->verifyPath($_GET['v'], true);
            if ($filePath) {
                $this->viewFile($filePath);
            } else {
                $this->addMessages('Error', 'Invalid file path for view.');
            }

        } elseif (isset($_POST['v']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $filePath = $this->verifyPath($_POST['v'], true);
            if ($filePath) {
                $this->viewFile($filePath);
            } else {
                $this->addMessages('Error', 'Invalid file path for view.');
            }

        } elseif (isset($_GET['d'])) {
            $filePath = $this->verifyPath($_GET['d'], true);
            if ($filePath) {
                $this->downloadFile($filePath);
            } else {
                $this->addMessages('Error', 'Invalid file path for download.');
            }

        } elseif (isset($_POST['d']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $filePath = $this->verifyPath($_POST['d'], true);
            if ($filePath) {
                $this->downloadFile($filePath);
            } else {
                $this->addMessages('Error', 'Invalid file path for download.');
            }

        } elseif (isset($_POST['rm']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $filePath = $this->verifyPath($_POST['rm'], true);
            if ($filePath) {
                $this->deleteFile($filePath);
            } else {
                $this->addMessages('Error', 'Invalid file path for deletion.');
            }

        } elseif (isset($_POST['upload']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $this->uploadFile();

        } elseif (isset($_POST['mkdir']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $dirPath = $this->verifyNewPath($_POST['mkdir']);
            if ($dirPath) {
            	// dir does not exists, we can create it
                $this->makeDirectory($dirPath);
            } else {
                $this->addMessages('Error', 'Invalid directory name.');
            }

        } elseif (isset($_POST['rmdir']) && $this->isValidCsrfToken($_POST['csrf_token'] ?? '')) {
            $dirPath = $this->verifyPath($_POST['rmdir'], false);
            if ($dirPath) {
                $this->removeDirectory($dirPath);
            } else {
                $this->addMessages('Error', 'Invalid directory path for removal.');
            }
        }
    }

    private function viewFile($fileName) {
        $filePathAbs = realpath($fileName);
//        $filePathAbs = realpath($this->basePathAbs . $this->currentPathRel . '/' . $fileName);

        if (!$filePathAbs || strpos($filePathAbs, $this->basePathAbs) !== 0 || !is_file($filePathAbs) || is_link($filePathAbs)) {
            $this->addMessages('Error', 'The file could not be viewed.');
            return;
        }

        // Check MIME type and restrict to allowed types
        // $mimeType = mime_content_type($filePathAbs);
        // $allowedMimeTypes = [
        //     'text/plain',
        //     'image/jpeg',
        //     'image/png',
        //     'application/pdf',
        // ];

        // if (!in_array($mimeType, $allowedMimeTypes, true)) {
        //     $this->addMessages('Error', 'The file type is not supported for viewing.');
        //     return;
        // }

        $mimeType = mime_content_type($filePathAbs);
        header('Content-Description: Inline File');
        header('Content-Type: ' . $mimeType);
        header('Content-Disposition: inline; filename="' . basename($filePathAbs) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filePathAbs));

//        ob_clean();
        flush();
        readfile($filePathAbs);
        exit(0);
    }

    private function downloadFile($fileName) {
        // if (!$this->isValidFileName($fileName)) {
        //     $this->addMessages('Error', 'Invalid file name.');
        //     return;
        // }

        $filePathAbs = realpath($fileName);

        if (!$filePathAbs || strpos($filePathAbs, $this->basePathAbs) !== 0 || !is_file($filePathAbs) || is_link($filePathAbs)) {
            $this->addMessages('Error', 'File not found: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
            return;
        }

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePathAbs) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filePathAbs));

        flush();
        readfile($filePathAbs);
        exit(0);
    }

    private function uploadFile() {
        $uploadDirAbs = realpath($this->basePathAbs . $this->currentPathRel);
        if (!$uploadDirAbs || strpos($uploadDirAbs, $this->basePathAbs) !== 0) {
            $this->addMessages('Error', 'Invalid upload directory');
            return;
        }

        $fileName = basename($_FILES['file']['name']);
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        if (in_array($fileExtension, $this->excludedExtensions)) {
            $this->addMessages('Error', 'Invalid file type.');
            return;
        }

        // $allowedExtensions = ['jpg', 'png', 'txt', 'pdf', 'svg', 'stl', 'doc', 'xls'];
        // if (!in_array($fileExtension, $allowedExtensions)) {
        //     $this->addMessages('Error', 'Invalid file type.');
        // }

        $targetFileAbs = $uploadDirAbs . '/' . $fileName;
        //$targetFileAbs = $uploadDirAbs . '/' . uniqid() . '_' . $fileName;

        if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFileAbs)) {
            $this->addMessages('Info', 'File uploaded successfully: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
        } else {
            $this->addMessages('Error', 'Failed to upload file: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
        }
    }

    private function deleteFile($fileName) {
        $filePathAbs = realpath($fileName);
        // $filePathAbs = realpath($this->basePathAbs . $this->currentPathRel . '/' . $fileName);
        if (!$filePathAbs || strpos($filePathAbs, $this->basePathAbs) !== 0 || !is_file($filePathAbs) || is_link($filePathAbs)) {
            $this->addMessages('Error', 'File not found: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
            return;
        }

        if (!unlink($filePathAbs)) {
            $this->addMessages('Error', 'Failed to delete file: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
            return;
        }
        $this->addMessages('Info', 'File deleted successfully: ' . htmlspecialchars($fileName, ENT_QUOTES, 'UTF-8'));
    }

    private function makeDirectory($dirName) {
        // Sanitize directory name to avoid malicious input
        $dirName = basename($dirName);
        $newDirPath = $dirName;
        $newDirPath = $this->basePathAbs . $this->currentPathRel . '/' . $dirName;

        // Resolve and validate the new directory path
        $resolvedPath = realpath(dirname($newDirPath)); // Get the real path of the parent directory
        if (!$resolvedPath || strpos($resolvedPath, $this->basePathAbs) !== 0) {
            $this->addMessages('Error', 'Invalid directory path.');
            return;
        }

        // Attempt to create the directory
        $HTMLdirName = htmlspecialchars($dirName, ENT_QUOTES, 'UTF-8');
        if (is_dir($newDirPath)) {
            $this->addMessages('Error', 'Directory already exists: ' . $HTMLdirName);
        } elseif (mkdir($newDirPath, 0705)) {
            $this->addMessages('Info', 'Directory created successfully: ' . $HTMLdirName);
        } else {
            $this->addMessages('Error', 'Failed to create directory: ' . $HTMLdirName);
        }
    }

    private function removeDirectory($dirName) {
        $dirPathAbs = realpath($dirName);
        
        $HTMLdirName = str_replace($this->basePathAbs . '/', '', $dirName);
        $HTMLdirName = htmlspecialchars($HTMLdirName, ENT_QUOTES, 'UTF-8');

        if (!$dirPathAbs || strpos($dirPathAbs, $this->basePathAbs) !== 0 || !is_dir($dirPathAbs) || is_link($dirPathAbs)) {
            $this->addMessages('Error', 'Cannot remove directory: ' . htmlspecialchars($HTMLdirName, ENT_QUOTES, 'UTF-8'));
            return;
        }

        if (!rmdir($dirPathAbs)) {
            $this->addMessages('Error', 'Failed to delete directory: ' . htmlspecialchars($HTMLdirName, ENT_QUOTES, 'UTF-8'));
            return;
        }
        $this->addMessages('Info', 'Directory removed successfully: ' . htmlspecialchars($HTMLdirName, ENT_QUOTES, 'UTF-8'));
    }

    public function renderDirectoryListing() {
        echo '<!DOCTYPE html>';
        echo '<html>';
        echo '<head>';
        echo '<meta charset="UTF-8">';
        echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">';
        echo '<title>files</title>';
        echo '<link rel="stylesheet" href="style.css">';
        echo '<link rel="icon" type="image/svg+xml" href="svg/favicon.svg">';
        echo '<script>';
        echo 'const timeout = 305000;';
        echo 'const logoutUrl = "?logout";';
	        echo 'function redirectToLogout() { window.location.href = logoutUrl; }';
        echo 'setTimeout(redirectToLogout, timeout);';
        echo '</script>';
        echo '</head>';
        echo '<body>';
        echo '<nav>';

        $this->printMessages();
        echo '<bar>';
        $this->renderDirectoryNav();
        echo '<a id="logout" href="?logout"></a>';
        echo '</bar>';
        echo '</nav>';

        echo '<listing>';

        $this->renderElementHeadline();

        $this->renderDirListing();

        $HTMLcurrentPath = htmlspecialchars($this->currentPathRel, ENT_QUOTES, 'UTF-8');

        $this->renderMkDir();
        $this->renderUpload();

        echo '</listing>';
        echo '</body>';
        echo '</html>';
    }

    private function renderDirectoryNav() {
        $pathSegments = explode('/', $this->currentPathRel);
        $navPath = '';

        foreach ($pathSegments as $segment) {
            if ($segment == "") {
                echo '<a href="/">Root</a>';
                continue;
            }
            $navPath .= '/' . $segment;
            $HTMLnavPath = htmlspecialchars($navPath, ENT_QUOTES, 'UTF-8');
            $HTMLsegment = htmlspecialchars($segment, ENT_QUOTES, 'UTF-8');
            echo '<a href="?p=' . $HTMLnavPath . '">' . $HTMLsegment . '</a>';
        }
    }

    private function renderElementHeadline() {
        echo '<name class="headline">Name</name>';
        echo '<size class="headline">Size</size>';
        echo '<date class="headline">Modified</date>';
        echo '<action class="headline"></action>';
    }

    private function renderDirListing() {
        $entries = [];

        if ($dir = opendir($this->basePathAbs . $this->currentPathRel)) {
            while (($entry = readdir($dir)) !== false) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $fullPath = $this->basePathAbs . $this->currentPathRel . '/' . $entry;
                $entries[] = [
                    'name' => $entry,
                    'isDir' => is_dir($fullPath),
                    'modified' => filemtime($fullPath),
                    'path' => $fullPath,
                ];
            }
            closedir($dir);
        }

        // find latest entry
        $latestName = null;
        $latestTime = 0;
        foreach ($entries as $entry) {
            if (/*!$entry['isDir'] && */ $entry['modified'] > $latestTime) {
                $latestTime = $entry['modified'];
                $latestName = $entry['name'];
             }
        }

        usort($entries, function ($a, $b) {
            if ($a['isDir'] === $b['isDir']) { // BOTH are folder OR files
                return $a['name'] <=> $b['name']; // name ASC
            }
            return $b['isDir'] <=> $a['isDir']; // folder > file
        });

        // output
        foreach ($entries as $entry) {
            $marker = ($entry['name'] === $latestName);
            if ($entry['isDir']) {
            	$this->renderElementDir($entry['name'], $marker);
            } else {
                $this->renderElementFile($entry['name'], $marker);
            }
        }
    }

    private function renderElementDir($entry, $marker = false) {
        $entryPath = $this->basePathAbs . $this->currentPathRel . '/' . $entry;
        $HTMLcurrentPath = htmlspecialchars($this->currentPathRel, ENT_QUOTES, 'UTF-8');
        $HTMLentryUrl = htmlspecialchars($this->currentPathRel . '/' . $entry, ENT_QUOTES, 'UTF-8');
        $HTMLentryName = htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');

	$class = $marker ? " marker" : "";
        echo '<a class="dir' . $class . '" href="?p=' . $HTMLentryUrl . '">' . $HTMLentryName . '</a>';
        echo '<size class="' . $class . '"></size>';        
        echo '<date class="' . $class . '">' . date("Y-m-d H:i:s", filemtime($entryPath)) . '</date>';
        echo '<action>';
        if (!$this->isPublic) {
            // Remove directory
            echo '<form method="POST">';
            echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
            echo '<input type="hidden" name="current_path" value="' . $HTMLcurrentPath . '">';
            echo '<input type="hidden" name="rmdir" value="' . $HTMLentryName . '">';
            echo '<button type="submit" class="rmdir">&nbsp;</button>';
            echo '</form>';
        }
        echo '</action>';
    }

    private function renderElementFile($entry, $marker = false) {
        $entryPath = $this->basePathAbs . $this->currentPathRel . '/' . $entry;
        $HTMLcurrentPath = htmlspecialchars($this->currentPathRel . '/', ENT_QUOTES, 'UTF-8');
        $HTMLentryUrl = htmlspecialchars($this->currentPathRel . '/' . $entry, ENT_QUOTES, 'UTF-8');
        $HTMLentryName = htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');

        $class = $marker ? " marker" : "";
        echo '<a class="file' . $class . '" target="_blank" rel="noopener noreferrer" href="?p=' . $HTMLcurrentPath . '&v=' . $HTMLentryName . '">' . $HTMLentryName . '</a>';
        echo '<size class="' . $class . '">' . $this->humanFileSize(filesize($entryPath)) . '</size>';
        echo '<date class="' . $class . '">' . date("Y-m-d H:i:s", filemtime($entryPath)) . '</date>';
        echo '<action>';
            // Download file
            echo '<form method="POST">';
            echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
            echo '<input type="hidden" name="current_path" value="' . $HTMLcurrentPath . '">';
            echo '<input type="hidden" name="d" value="' . $HTMLentryName . '">';
            echo '<button type="submit" class="download">&nbsp;</button>';
            echo '</form>';
            // Remove file
            if (!$this->isPublic) {
                echo '<form method="POST">';
                echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
                echo '<input type="hidden" name="current_path" value="' . $HTMLcurrentPath . '">';
                echo '<input type="hidden" name="rm" value="' . $HTMLentryName . '">';
                echo '<button type="submit" class="rm">&nbsp;</button>';
                echo '</form>';
            }
        echo '</action>';
    }

    private function renderMkDir() {
        $HTMLcurrentPath = htmlspecialchars($this->currentPathRel, ENT_QUOTES, 'UTF-8');

        echo '<form method="POST" id="mkdir">';
        echo '<cmd class="mkdir">';
            echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
            echo '<input type="hidden" name="current_path" value="' . $HTMLcurrentPath . '">';
            echo '<input type="text" name="mkdir" placeholder="New Directory Name" required>';
        echo '</cmd>';
        echo '<button class="action mkdir" type="submit">&nbsp;</button>';
        echo '</form>';
    }

    private function renderUpload() {
        $HTMLcurrentPath = htmlspecialchars($this->currentPathRel, ENT_QUOTES, 'UTF-8');

        echo '<form method="POST" enctype="multipart/form-data" class="formInline" id="upload">';
        echo '<cmd class="upload">';
            echo '<input type="hidden" name="csrf_token" value="' . $this->csrfToken . '">';
            echo '<input type="hidden" name="current_path" value="' . $HTMLcurrentPath . '">';
            echo '<input type="hidden" name="upload" value="file">';
            echo '<input type="file" name="file">';
        echo '</cmd>';
        echo '<button class="action upload" type="submit">&nbsp;</button>';
        echo '</form>';
    }

    private function humanFileSize($size, $unit = "") {
        if ((!$unit && $size >= 1 << 30) || $unit == " GB")
            return number_format($size / (1 << 30), 2) . " GB";
        if ((!$unit && $size >= 1 << 20) || $unit == " MB")
            return number_format($size / (1 << 20), 2) . " MB";
        if ((!$unit && $size >= 1 << 10) || $unit == " kB")
            return number_format($size / (1 << 10), 2) . " kB";
        return number_format($size) . "  B";
    }
}

/*
if (PHP_DISABLE === true) {
    $manager = new DirectoryManager(BASE_DIR);
    $manager->renderLoginForm(true);
    echo "<div></div>";
    exit();
}
*/

$manager = new DirectoryManager(BASE_DIR);
$manager->handleRequest();
$manager->renderDirectoryListing();

echo "<div></div>";
