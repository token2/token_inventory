<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define whether running in local/PHP-Desktop environment
define('LOCAL_APP', 0); // Set to 1 for PHP-Desktop, 0 for web server

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    // Clear credential cookies
    setcookie('tenantId', '', time() - 3600, '/', '', true, true);
    setcookie('clientId', '', time() - 3600, '/', '', true, true);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Handle settings update via form submission
if (isset($_GET['action']) && $_GET['action'] === 'update_settings_form') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $tenantId = trim($_POST['tenantId']);
        $clientId = trim($_POST['clientId']);
        $clientSecret = trim($_POST['clientSecret']);
        
        // Save tenant ID and client ID in cookies (30 days)
        setcookie('tenantId', $tenantId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        setcookie('clientId', $clientId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        
        // Keep only client secret in session
        $_SESSION['clientSecret'] = $clientSecret;
        $_SESSION['showLogs'] = isset($_POST['showLogs']) ? true : false;
        
        // Redirect back to main page with success message
        header('Location: ' . $_SERVER['PHP_SELF'] . '?settings_updated=1');
        exit;
    }
}

// Handle settings update via AJAX (keeping both for compatibility)
if (isset($_GET['action']) && $_GET['action'] === 'update_settings') {
    header('Content-Type: application/json');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $tenantId = trim($_POST['tenantId']);
        $clientId = trim($_POST['clientId']);
        $clientSecret = trim($_POST['clientSecret']);
        
        // Save tenant ID and client ID in cookies (30 days)
        setcookie('tenantId', $tenantId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        setcookie('clientId', $clientId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        
        // Keep only client secret in session
        $_SESSION['clientSecret'] = $clientSecret;
        $_SESSION['showLogs'] = isset($_POST['showLogs']) ? true : false;
        
        echo json_encode(['success' => true, 'message' => 'Settings updated successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    }
    exit;
}

// Check for saved credentials in cookies
$savedTenantId = $_COOKIE['tenantId'] ?? '';
$savedClientId = $_COOKIE['clientId'] ?? '';

// Ask for Microsoft credentials if not stored
if (empty($savedTenantId) || empty($savedClientId) || !isset($_SESSION['clientSecret'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['tenantId'])) {
        $tenantId = trim($_POST['tenantId']);
        $clientId = trim($_POST['clientId']);
        $clientSecret = trim($_POST['clientSecret']);
        
        // Save tenant ID and client ID in cookies (30 days)
        setcookie('tenantId', $tenantId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        setcookie('clientId', $clientId, time() + (30 * 24 * 60 * 60), '/', '', true, true);
        
        // Keep only client secret in session
        $_SESSION['clientSecret'] = $clientSecret;
        $_SESSION['showLogs'] = isset($_POST['showLogs']) ? true : false;
        
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
echo '<!DOCTYPE html>
<html>
<head>
    <title>Enter Credentials</title>
    <link rel="stylesheet" href="assets/bootstrap.min.css">
    <script src="assets/bootstrap.bundle.min.js"></script>
	<link rel="shortcut icon" href="favico.png">
</head>
<body>
<div class="container mt-4">
    <div class="row">
        <!-- Form column -->
        <div class="col-md-6">
            <h3>Enter Microsoft Graph Credentials</h3>
            <form method="POST">
                <div class="form-group mb-3">
                    <label>Tenant ID:</label>
                    <input type="text" name="tenantId" class="form-control" value="' . htmlspecialchars($savedTenantId) . '" required>
                </div>
                <div class="form-group mb-3">
                    <label>Client ID:</label>
                    <input type="text" name="clientId" class="form-control" value="' . htmlspecialchars($savedClientId) . '" required>
                </div>
                <div class="form-group mb-3">
                    <label>Client Secret:</label>
                    <input type="password" name="clientSecret" class="form-control" required>
                </div>
                <div class="form-group mb-3">
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="showLogs" name="showLogs" checked>
                        <label class="form-check-label" for="showLogs">
                            Show operation logs
                        </label>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary mt-2">Save & Continue</button>
            </form>
        </div>

        <!-- README Tabs column -->
        <div class="col-md-6">
            <h4><br></h4>
            
          <div class="step">
    <strong>API permissions  required:</strong>
    <ul>
        <li><code>Policy.ReadWrite.AuthenticationMethod</code></li>
        <li><code>UserAuthenticationMethod.ReadWrite.All</code></li>
        <li><code>User.Read.All</code></li>
        <li><code>Directory.Read.All</code></li>
    </ul>
    <strong>Grant admin consent for all permissions</strong>
</div>
        </div>
    </div>
</div><div style="position: fixed; bottom: 10px; right: 10px; font-size: 14px; color: #555;">
  &copy; Token2
</div>
</body>
</html>';
exit;

}

// Initialize showLogs setting if not set
if (!isset($_SESSION['showLogs'])) {
    $_SESSION['showLogs'] = true;
}

// Credentials - get from cookies and session
$tenantId = $_COOKIE['tenantId'] ?? '';
$clientId = $_COOKIE['clientId'] ?? '';
$clientSecret = $_SESSION['clientSecret'] ?? '';

// Get Access Token
function getAccessToken($tenantId, $clientId, $clientSecret)
{
    $url = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token";
    $data = ['grant_type' => 'client_credentials', 'client_id' => $clientId, 'client_secret' => $clientSecret, 'scope' => 'https://graph.microsoft.com/.default'];
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for authentication errors
    if ($httpCode !== 200 || !isset($resp['access_token'])) {
        $error = $resp['error'] ?? 'unknown_error';
        $errorDescription = $resp['error_description'] ?? 'Unknown authentication error';
        
        // Log the specific error for debugging
        error_log("Authentication failed: HTTP $httpCode - Error: $error - Description: $errorDescription");
        
        // Check for common credential errors
        if (strpos($errorDescription, 'AADSTS70002') !== false || strpos($errorDescription, 'invalid_client') !== false) {
            throw new Exception("Invalid Client ID or Client Secret. Please check your credentials in Settings.");
        } elseif (strpos($errorDescription, 'AADSTS90002') !== false || strpos($errorDescription, 'invalid_tenant') !== false) {
            throw new Exception("Invalid Tenant ID. Please check your tenant ID in Settings.");
        } elseif (strpos($error, 'invalid_client') !== false) {
            throw new Exception("Invalid credentials. Please verify your Tenant ID, Client ID, and Client Secret in Settings.");
        } else {
            throw new Exception("Authentication failed: " . $errorDescription);
        }
    }
    
    return $resp['access_token'];
}

// Graph API functions
function fetchTokens($accessToken)
{
    $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices";
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for permission errors
    if ($httpCode === 403 || $httpCode === 401) {
        $error = $resp['error'] ?? [];
        $errorCode = $error['code'] ?? '';
        $errorMessage = $error['message'] ?? '';
        
        // Detect specific permission issues
        if (strpos($errorCode, 'Authorization_RequestDenied') !== false || 
            strpos($errorMessage, 'Insufficient privileges') !== false ||
            strpos($errorMessage, 'Access denied') !== false) {
            
            throw new Exception("Missing API Permissions: Your application doesn't have the required Microsoft Graph permissions. Please ensure these permissions are granted and admin consent is provided:\n\n" .
                "Required permissions for Hardware OATH Tokens:\n" .
                "• Policy.ReadWrite.AuthenticationMethod (Application)\n" .
                "• AuthenticationMethodDevice.ReadWrite.All (Application)\n" .
                "• Directory.Read.All (Application)\n" .
                "• User.Read.All (Application)\n\n" .
                "Steps to fix:\n" .
                "1. Go to Azure Portal → App Registrations → Your App\n" .
                "2. Select 'API permissions'\n" .
                "3. Add the missing permissions listed above\n" .
                "4. Click 'Grant admin consent for [tenant]'\n\n" .
                "Technical details: " . $errorMessage);
        }
        
        // Generic permission error
        throw new Exception("Permission Error: " . $errorMessage . " (HTTP $httpCode)");
    }
    
    return ['value' => $resp['value'] ?? [], 'log' => $resp];
}

function importTokens($accessToken, $data)
{
    $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices";
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $resp = json_decode(curl_exec($ch), true);
    curl_close($ch);
    return $resp;
}

function importCSVTokens($accessToken, $csvData, $importMode = 'import_assign_activate') {
    $results = [];
    $lines = explode("\n", $csvData);
    
    // Remove BOM if present
    $lines[0] = preg_replace('/^\xEF\xBB\xBF/', '', $lines[0]);
    
    $headers = str_getcsv(array_shift($lines));
    
    // Trim whitespace from headers
    $headers = array_map('trim', $headers);

    foreach ($lines as $lineNum => $line) {
        if (empty(trim($line))) continue;
        
        $data = str_getcsv($line);
        
        // Skip if not enough columns
        if (count($data) < count($headers)) {
            $results["line_" . ($lineNum + 2)] = [
                'import_success' => false,
                'import_log' => ['error' => 'Insufficient columns in CSV line'],
                'token_id' => null,
            ];
            continue;
        }
        
        $data = array_combine($headers, $data);

        $upn = trim($data['upn'] ?? '');
        $serialNumber = trim($data['serial number'] ?? '');
        $secretKey = trim($data['secret key'] ?? '');
        $timeInterval = (int)($data['timeinterval'] ?? 30);
        $manufacturer = trim($data['manufacturer'] ?? '');
        $model = trim($data['model'] ?? '');

        // Validate required fields
        if (empty($serialNumber) || empty($secretKey)) {
            $results[$serialNumber ?: "line_" . ($lineNum + 2)] = [
                'import_success' => false,
                'import_log' => ['error' => 'Missing required fields: serial number or secret key'],
                'token_id' => null,
            ];
            continue;
        }

        // For modes that require assignment, validate UPN
        if (($importMode === 'import_assign' || $importMode === 'import_assign_activate') && empty($upn)) {
            $results[$serialNumber] = [
                'import_success' => false,
                'import_log' => ['error' => 'UPN is required for assignment mode'],
                'token_id' => null,
            ];
            continue;
        }

        // Process secret key - remove spaces and convert to uppercase
        $secretKey = strtoupper(str_replace(' ', '', $secretKey));
        
        // Validate base32 format
        if (!preg_match('/^[A-Z2-7]+$/', $secretKey)) {
            $results[$serialNumber] = [
                'import_success' => false,
                'import_log' => ['error' => 'Invalid secret key format. Must be Base32 (A-Z, 2-7)'],
                'token_id' => null,
            ];
            continue;
        }

        // Remove any existing padding and ensure proper length
        $secretKey = rtrim($secretKey, '=');
        
        // Validate minimum length (TOTP secrets should be at least 16 characters)
        if (strlen($secretKey) < 16) {
            $results[$serialNumber] = [
                'import_success' => false,
                'import_log' => ['error' => 'Secret key too short. Must be at least 16 characters'],
                'token_id' => null,
            ];
            continue;
        }

        // Determine hash function based on secret key length
        $hashFunction = strlen($secretKey) <= 32 ? 'hmacsha1' : 'hmacsha256';

        $tokenData = [
            "displayName" => "$manufacturer $model - $serialNumber", // Required property
            "serialNumber" => $serialNumber,
            "manufacturer" => $manufacturer,
            "model" => $model,
            "secretKey" => $secretKey, // Use raw base32 string
            "timeIntervalInSeconds" => $timeInterval,
            "hashFunction" => $hashFunction, // Set based on secret key length
        ];

        $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices";
        $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($tokenData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $resp = json_decode(curl_exec($ch), true);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $tokenId = $resp['id'] ?? null;
        $results[$serialNumber] = [
            'import_success' => ($httpCode === 200 || $httpCode === 201),
            'import_log' => $resp,
            'token_id' => $tokenId,
            'http_code' => $httpCode,
            'request_data' => $tokenData, // Include request for debugging
            'import_mode' => $importMode,
        ];

        // Only proceed with assignment if import was successful and mode requires it
        if ($tokenId && ($importMode === 'import_assign' || $importMode === 'import_assign_activate') && $upn) {
            // Assign the token to the user
            $assignUrl = "https://graph.microsoft.com/beta/users/$upn/authentication/hardwareOathMethods";
            $assignData = ["device" => ["id" => $tokenId]];

            $assignCh = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
            curl_setopt($assignCh, CURLOPT_URL, $assignUrl);
            curl_setopt($assignCh, CURLOPT_POST, true);
            curl_setopt($assignCh, CURLOPT_POSTFIELDS, json_encode($assignData));
            curl_setopt($assignCh, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
            curl_setopt($assignCh, CURLOPT_RETURNTRANSFER, true);
            $assignResp = json_decode(curl_exec($assignCh), true);
            $assignHttpCode = curl_getinfo($assignCh, CURLINFO_HTTP_CODE);
            curl_close($assignCh);

            $results[$serialNumber]['assign_success'] = ($assignHttpCode === 200 || $assignHttpCode === 201);
            $results[$serialNumber]['assign_log'] = $assignResp;
            $results[$serialNumber]['assign_http_code'] = $assignHttpCode;

            // Only attempt activation if assignment was successful and mode requires it
            if ($results[$serialNumber]['assign_success'] && $importMode === 'import_assign_activate') {
                // Activate the token
                $activateUrl = "https://graph.microsoft.com/beta/users/$upn/authentication/hardwareOathMethods/$tokenId/activate";
                $activateData = ["verificationCode" => generateTOTPCode($secretKey)]; //  

                $activateCh = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
                curl_setopt($activateCh, CURLOPT_URL, $activateUrl);
                curl_setopt($activateCh, CURLOPT_POST, true);
                curl_setopt($activateCh, CURLOPT_POSTFIELDS, json_encode($activateData));
                curl_setopt($activateCh, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
                curl_setopt($activateCh, CURLOPT_RETURNTRANSFER, true);
                $activateResp = json_decode(curl_exec($activateCh), true);
                $activateHttpCode = curl_getinfo($activateCh, CURLINFO_HTTP_CODE);
                curl_close($activateCh);

                $results[$serialNumber]['activate_success'] = ($activateHttpCode === 200 || $activateHttpCode === 204);
                $results[$serialNumber]['activate_log'] = $activateResp;
                $results[$serialNumber]['activate_http_code'] = $activateHttpCode;
            }
        }
    }

    return $results;
}

function getUsers($accessToken, $query = '') {
    // Enhanced debugging function
    $debugInfo = [
        'query' => $query,
        'access_token_length' => strlen($accessToken),
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    // Build the filter properly
    if (!empty($query)) {
        $filter = "startswith(displayName,'$query') or startswith(userPrincipalName,'$query')";
        $url = "https://graph.microsoft.com/v1.0/users?\$top=50&\$filter=" . urlencode($filter);
    } else {
        // If no query, get all users (first 50)
        $url = "https://graph.microsoft.com/v1.0/users?\$top=50";
    }
    
    $debugInfo['url'] = $url;
    
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); } else { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
    
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_VERBOSE, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    $curlInfo = curl_getinfo($ch);
    curl_close($ch);
    
    $debugInfo['http_code'] = $httpCode;
    $debugInfo['curl_error'] = $curlError;
    $debugInfo['response_length'] = strlen($response);
    $debugInfo['response_preview'] = substr($response, 0, 200);
    
    // Log debug info
    error_log("getUsers Debug: " . json_encode($debugInfo));
    
    // Check for curl errors
    if ($response === false) {
        error_log("CURL Error in getUsers: " . $curlError);
        return [
            'debug' => $debugInfo, 
            'error' => 'CURL Error: ' . $curlError,
            'users' => []
        ];
    }
    
    // Check for HTTP errors
    if ($httpCode !== 200) {
        error_log("HTTP Error in getUsers: HTTP $httpCode - Response: " . $response);
        
        // Parse response for permission errors
        $resp = json_decode($response, true);
        if ($httpCode === 403 || $httpCode === 401) {
            $error = $resp['error'] ?? [];
            $errorCode = $error['code'] ?? '';
            $errorMessage = $error['message'] ?? '';
            
            if (strpos($errorCode, 'Authorization_RequestDenied') !== false || 
                strpos($errorMessage, 'Insufficient privileges') !== false) {
                return [
                    'debug' => $debugInfo, 
                    'error' => 'Missing Permission: Your application needs User.Read.All permission to list users. Please add this permission in Azure Portal → App Registrations → API permissions.',
                    'permission_error' => true,
                    'users' => []
                ];
            }
        }
        
        return [
            'debug' => $debugInfo, 
            'error' => "HTTP $httpCode", 
            'response' => $response,
            'users' => []
        ];
    }
    
    $resp = json_decode($response, true);
    
    // Check for JSON decode errors
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Decode Error in getUsers: " . json_last_error_msg());
        return [
            'debug' => $debugInfo, 
            'error' => 'JSON Error: ' . json_last_error_msg(),
            'users' => []
        ];
    }
    
    $debugInfo['user_count'] = count($resp['value'] ?? []);
    
    // SUCCESS - return users without debug info
    return [
        'users' => $resp['value'] ?? [],
        'success' => true
    ];
}

function assignToken($accessToken, $userId, $tokenId)
{
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods";
    $data = ["device" => ["id" => $tokenId]];
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for permission errors
    if ($httpCode === 403 || $httpCode === 401) {
        $error = $resp['error'] ?? [];
        $errorMessage = $error['message'] ?? '';
        
        if (strpos($errorMessage, 'Insufficient privileges') !== false) {
            return [
                'success' => false, 
                'log' => $resp, 
                'permission_error' => 'Missing Permission: Your application needs AuthenticationMethodDevice.ReadWrite.All permission to assign tokens to users.'
            ];
        }
    }
    
    return ['success' => ($httpCode === 200 || $httpCode === 201), 'log' => $resp];
}

function activateToken($accessToken, $userId, $tokenId, $code)
{
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods/$tokenId/activate";
    $data = ["verificationCode" => $code];
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken", "Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for permission errors
    if ($httpCode === 403 || $httpCode === 401) {
        $error = $resp['error'] ?? [];
        $errorMessage = $error['message'] ?? '';
        
        if (strpos($errorMessage, 'Insufficient privileges') !== false) {
            return [
                'success' => false, 
                'log' => $resp, 
                'permission_error' => 'Missing Permission: Your application needs AuthenticationMethodDevice.ReadWrite.All permission to activate tokens.'
            ];
        }
    }
    
    return ['success' => ($httpCode === 200 || $httpCode === 204), 'log' => $resp];
}

function unassignToken($accessToken, $userId, $tokenId)
{
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods/$tokenId";
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for permission errors
    if ($httpCode === 403 || $httpCode === 401) {
        $error = $resp['error'] ?? [];
        $errorMessage = $error['message'] ?? '';
        
        if (strpos($errorMessage, 'Insufficient privileges') !== false) {
            return [
                'success' => false, 
                'log' => $resp, 
                'permission_error' => 'Missing Permission: Your application needs AuthenticationMethodDevice.ReadWrite.All permission to unassign tokens.'
            ];
        }
    }
    
    return ['success' => ($httpCode === 200 || $httpCode === 204), 'log' => $resp];
}

function deleteToken($accessToken, $tokenId)
{
    $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices/$tokenId";
    $ch = curl_init(); if (LOCAL_APP  == 1 ) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $accessToken"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resp = json_decode($response, true);
    
    // Check for permission errors
    if ($httpCode === 403 || $httpCode === 401) {
        $error = $resp['error'] ?? [];
        $errorMessage = $error['message'] ?? '';
        
        if (strpos($errorMessage, 'Insufficient privileges') !== false) {
            return [
                'success' => false, 
                'log' => $resp, 
                'permission_error' => 'Missing Permission: Your application needs Policy.ReadWrite.AuthenticationMethod permission to delete tokens.'
            ];
        }
    }
    
    return ['success' => ($httpCode === 200 || $httpCode === 204), 'log' => $resp];
}

function generateTOTPCode($base32Secret, $timeInterval = 30) {
    try {
        // Determine hash algorithm based on secret length (like JavaScript version)
        $algorithm = strlen($base32Secret) <= 32 ? 'sha1' : 'sha256';
        
        // Base32 decode
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32CharsFlipped = array_flip(str_split($base32Chars));
        
        $paddedSecret = $base32Secret;
        $remainder = strlen($paddedSecret) % 8;
        if ($remainder > 0) {
            $paddedSecret .= str_repeat('=', 8 - $remainder);
        }
        
        $binaryString = '';
        for ($i = 0; $i < strlen($paddedSecret); $i += 8) {
            $chunk = substr($paddedSecret, $i, 8);
            if ($chunk === '========') break;
            
            $binaryChunk = '';
            for ($j = 0; $j < strlen($chunk); $j++) {
                if ($chunk[$j] === '=') break;
                if (!isset($base32CharsFlipped[$chunk[$j]])) {
                    return false; // Invalid character
                }
                $binaryChunk .= str_pad(decbin($base32CharsFlipped[$chunk[$j]]), 5, '0', STR_PAD_LEFT);
            }
            
            // Convert binary string to bytes
            for ($k = 0; $k < strlen($binaryChunk); $k += 8) {
                if (strlen($binaryChunk) - $k >= 8) {
                    $binaryString .= chr(bindec(substr($binaryChunk, $k, 8)));
                }
            }
        }
        
        // Get current time counter
        $timeCounter = floor(time() / $timeInterval);
        
        // Create time counter as 8-byte big-endian
        $timeBytes = pack('N*', 0, $timeCounter);
        
        // Generate HMAC with appropriate algorithm
        $hash = hash_hmac($algorithm, $timeBytes, $binaryString, true);
        
        // Dynamic truncation
        $hashLength = strlen($hash);
        $offset = ord($hash[$hashLength - 1]) & 0x0f;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
        
        return str_pad($code, 6, '0', STR_PAD_LEFT);
        
    } catch (Exception $e) {
        error_log("TOTP generation error: " . $e->getMessage());
        return false;
    }
}

// Initialize message variables
$message = '';
$csvMessage = '';
$importLog = null;
$csvImportLog = null;
$showMessages = false; // Only show messages immediately after the relevant operation

$initialMessage = ''; 

// Handle AJAX - these should not show persistent messages
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    try {
        $accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage(), 'credential_error' => true]);
        exit;
    }
    
    $post = $_POST;
    $res = ['success' => false, 'log' => ''];
    
    switch ($_GET['action']) {
        case 'get_users':
            $query = $_GET['query'] ?? '';
            $result = getUsers($accessToken, $query);
            
            // Check if the result contains success indicator
            if (isset($result['success']) && $result['success']) {
                $res = ['success' => true, 'users' => $result['users']];
            } else {
                // Error case - has debug info
                $res = [
                    'success' => false, 
                    'users' => $result['users'] ?? [], 
                    'debug' => $result['debug'] ?? null,
                    'error' => $result['error'] ?? 'Unknown error'
                ];
            }
            break;
        case 'assign_token':
            $res = assignToken($accessToken, $post['user_id'] ?? '', $post['token_id'] ?? '');
            break;
        case 'activate_token':
            $res = activateToken($accessToken, $post['user_id'] ?? '', $post['token_id'] ?? '', $post['verification_code'] ?? '');
            break;
        case 'unassign_token':
            $res = unassignToken($accessToken, $post['user_id'] ?? '', $post['token_id'] ?? '');
            break;
        case 'delete_token':
            $res = deleteToken($accessToken, $post['token_id'] ?? '');
            break;
        case 'import_csv':
            $csvData = $post['csv_data'] ?? '';
            $importMode = $post['import_mode'] ?? 'import_assign_activate';
            $res = ['success' => true, 'log' => importCSVTokens($accessToken, $csvData, $importMode)];
            break;
    }
    echo json_encode($res);
    exit;
}

// Handle file uploads - these SHOULD show persistent messages only for their specific operations
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Handle JSON import
        if (isset($_FILES['importFile'])) {
            $data = json_decode(file_get_contents($_FILES['importFile']['tmp_name']), true);
            if ($data) {
                $accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
                $importLog = [
                    'action' => 'Import Tokens',
                    'request' => $data,
                    'response' => importTokens($accessToken, $data),
                ];
                $message = ($importLog['response'] ? 'Tokens imported' : 'Failed import');
                $showMessages = true; // Flag to show this specific message
            } else {
                $message = 'Invalid JSON';
                $showMessages = true;
            }
        }
        // Handle CSV file upload
        elseif (isset($_FILES['csvFile'])) {
            $csvData = file_get_contents($_FILES['csvFile']['tmp_name']);
            $importMode = $_POST['import_mode'] ?? 'import_assign_activate';
            if ($csvData !== false) {
                $accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
                $csvImportLog = [
                    'action' => 'Import CSV Tokens',
                    'filename' => $_FILES['csvFile']['name'],
                    'import_mode' => $importMode,
                    'response' => importCSVTokens($accessToken, $csvData, $importMode),
                ];
                $csvMessage = 'CSV Tokens imported from file: ' . $_FILES['csvFile']['name'] . ' (Mode: ' . $importMode . ')';
                $showMessages = true; // Flag to show this specific message
            } else {
                $csvMessage = 'Failed to read CSV file';
                $showMessages = true;
            }
        }
        // Handle textarea CSV import (keeping both options) - but only if no file was uploaded
        elseif (isset($_POST['csv_data'])) {
            $csvData = $_POST['csv_data'];
            $importMode = $_POST['import_mode'] ?? 'import_assign_activate';
            $accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
            $csvImportLog = [
                'action' => 'Import CSV Tokens',
                'request' => $csvData,
                'import_mode' => $importMode,
                'response' => importCSVTokens($accessToken, $csvData, $importMode),
            ];
            $csvMessage = 'CSV Tokens imported from textarea (Mode: ' . $importMode . ')';
            $showMessages = true; // Flag to show this specific message
        }
    } catch (Exception $e) {
        // Handle credential errors
        $credentialError = $e->getMessage();
        if (isset($_FILES['importFile'])) {
            $message = 'Authentication failed: ' . $credentialError;
            $showMessages = true;
        } elseif (isset($_FILES['csvFile']) || isset($_POST['csv_data'])) {
            $csvMessage = 'Authentication failed: ' . $credentialError;
            $showMessages = true;
        }
    }
}

// Fetch tokens and capture the response for logging
$credentialError = null;
$tokens = [];
$initialLog = null;

try {
    $fetchResult = fetchTokens(getAccessToken($tenantId, $clientId, $clientSecret));
    $tokens = $fetchResult['value'];
    $initialLog = [
        'action' => 'Initial Load',
        'endpoint' => 'fetchTokens',
        'response' => $fetchResult['log'],
    ];
} catch (Exception $e) {
    $credentialError = $e->getMessage();
    $initialLog = [
        'action' => 'Initial Load',
        'endpoint' => 'fetchTokens',
        'error' => $credentialError,
    ];
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Hardware Tokens</title>
    <link rel="stylesheet" href="assets/bootstrap.min.css">
    <link rel="stylesheet" href="assets/dataTables.bootstrap4.min.css">
    <script src="assets/jquery-3.6.0.min.js"></script>
    <script src="assets/jquery.dataTables.min.js"></script>
    <script src="assets/dataTables.bootstrap4.min.js"></script>
    <script src="assets/bootstrap.min.js"></script>
	<link rel="shortcut icon" href="favico.png">
    <style>
	
	body{
    background-image:url('assets/bg.png');
    background-attachment:fixed;
    background-repeat: no-repeat;
    background-size: cover;
}


        .log-container {
            max-height: 200px;
            overflow-y: auto;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
        }
        .loading-spinner {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.7);
            z-index: 1050;
            justify-content: center;
            align-items: center;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-radius: 50%;
            border-top-color: #007bff;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .log-entry {
            border-bottom: 1px solid #dee2e6;
            padding: 15px 0;
        }
        .log-entry:last-child {
            border-bottom: none;
        }
        .log-timestamp {
            font-size: 0.85em;
            color: #6c757d;
        }
        .log-status {
            font-weight: bold;
        }
        .log-status.success {
            color: #28a745;
        }
        .log-status.error {
            color: #dc3545;
        }
        .log-status.info {
            color: #17a2b8;
        }
        .log-details {
            background: #f8f9fa;
            border-radius: 4px;
            padding: 10px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            max-height: 200px;
            overflow-y: auto;
        }
        .auto-refresh-notice {
            background: #e3f2fd;
            border: 1px solid #90caf9;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            text-align: center;
            color: #1565c0;
        }
        .import-tabs {
            border-bottom: 1px solid #dee2e6;
            margin-bottom: 20px;
        }
        .import-tabs .nav-link {
            border-bottom: 2px solid transparent;
        }
        .import-tabs .nav-link.active {
            border-bottom-color: #007bff;
            background: none;
        }
		
        #userResults {
            max-height: 200px;
            overflow-y: auto;
            margin-top: -1px;
            border: 1px solid #ced4da;
            border-radius: 0 0 4px 4px;
            background: white;
            position: absolute;
            width: calc(100% - 30px);
            z-index: 1000;
        }
        #userResults .list-group-item {
            cursor: pointer;
            padding: 8px 15px;
            border: none;
            border-bottom: 1px solid #ced4da;
        }
        #userResults .list-group-item:hover {
            background: #f8f9fa;
        }
        #userResults .list-group-item:last-child {
            border-bottom: none;
        }
        
        .import-mode-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
        }
		
    </style>
</head>
<body>
    <div class="container mt-4"><h4><img src="favico.png"> TOTP Tokens Inventory</h4>
	   <div class="float-left">
            <a href=index.php class="btn btn-outline-danger" title=refresh>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-arrow-clockwise" viewBox="0 0 16 16">
  <path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2z"/>
  <path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466"/>
</svg></a>
			
			</div>
        <div class="float-right">
            <button class="btn btn-secondary mb-3" data-toggle="modal" data-target="#settingsModal">⚙️ Settings</button>
            <button class="btn btn-primary mb-3" data-toggle="modal" data-target="#importModal">JSON Operations</button>
            <button class="btn btn-info mb-3" data-toggle="modal" data-target="#importCSVModal">CSV Operations</button>
            <a href="?logout" class="btn btn-danger mb-3">Clear session</a>
        </div>
        <br style="clear:both">
        
        <!-- Only show messages for file upload operations, not AJAX operations -->
        <?php if (isset($_GET['settings_updated'])) : ?>
            <div class="alert alert-success alert-dismissible fade show">
                Settings updated successfully!
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>
        
        <?php if ($credentialError) : ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <strong>Authentication Error:</strong> <?= htmlspecialchars($credentialError) ?>
                <br><small>Please check your credentials in <button class="btn btn-link p-0" data-toggle="modal" data-target="#settingsModal">Settings</button></small>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>
        
        <?php if ($message && ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['importFile']))) : ?>
            <div class="alert alert-<?= strpos($message, 'Failed') !== false || strpos($message, 'Authentication failed') !== false ? 'danger' : 'success' ?> alert-dismissible fade show">
                <?= htmlspecialchars($message) ?>
                <?php if (strpos($message, 'Authentication failed') !== false) : ?>
                    <br><small>Please check your credentials in <button class="btn btn-link p-0" data-toggle="modal" data-target="#settingsModal">Settings</button></small>
                <?php endif; ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>
        
        <?php if ($csvMessage && ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_FILES['csvFile']) || isset($_POST['csv_data'])))) : ?>
            <div class="alert alert-<?= strpos($csvMessage, 'Authentication failed') !== false ? 'danger' : 'success' ?> alert-dismissible fade show">
                <?= htmlspecialchars($csvMessage) ?>
                <?php if (strpos($csvMessage, 'Authentication failed') !== false) : ?>
                    <br><small>Please check your credentials in <button class="btn btn-link p-0" data-toggle="modal" data-target="#settingsModal">Settings</button></small>
                <?php endif; ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>
        
        <br style="clear:both">
        
        <!-- Logs Section -->
        <div class="card mb-4" id="logsSection" style="display: none;">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">Operation Logs</h6>
                <div>
                    <button class="btn btn-sm btn-outline-secondary" onclick="clearLogs()">Clear Logs</button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="toggleLogs()">Hide</button>
                </div>
            </div>
            <div class="card-body">
                <div id="logsContainer" style="max-height: 400px; overflow-y: auto;">
                    <!-- Logs will be populated here -->
                </div>
            </div>
        </div>
        
        <!-- Settings Modal -->
        <div class="modal fade" id="settingsModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5>Settings</h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <form method="POST" action="?action=update_settings_form">
                        <div class="modal-body">
                            <div class="form-group">
                                <label>Tenant ID:</label>
                                <input type="text" name="tenantId" class="form-control" value="<?= htmlspecialchars($tenantId) ?>" required>
                            </div>
                            <div class="form-group">
                                <label>Client ID:</label>
                                <input type="text" name="clientId" class="form-control" value="<?= htmlspecialchars($clientId) ?>" required>
                            </div>
                            <div class="form-group">
                                <label>Client Secret:</label>
                                <input type="password" name="clientSecret" class="form-control" value="<?= htmlspecialchars($clientSecret) ?>" required>
                            </div>
                            <hr>
                            <div class="form-group">
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="showLogsSettings" name="showLogs" value="1" <?= $_SESSION['showLogs'] ? 'checked' : '' ?>>
                                    <label class="form-check-label" for="showLogsSettings">
                                        Show operation logs after each action
                                    </label>
                                    <small class="form-text text-muted">
                                        When enabled, detailed logs will be displayed after operations. When disabled, only success/error messages will be shown.
                                    </small>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-primary">Save Settings</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Import Modal -->
        <div class="modal fade" id="importModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5>Import Tokens</h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <form method="POST" enctype="multipart/form-data">
                            <input type="file" name="importFile" accept="application/json" class="form-control" required><br>
                            <button type="submit" class="btn btn-primary">Upload</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <!-- Import CSV Modal -->
        <div class="modal fade" id="importCSVModal">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5>Import CSV Tokens</h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <!-- Import Mode Selection -->
                        <div class="import-mode-section">
                            <h6>Import Mode</h6>
                            <div class="form-group">
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="import_mode" id="import_only" value="import_only">
                                    <label class="form-check-label" for="import_only">
                                        <strong>Import Only</strong> - Just create tokens in the tenant (UPN optional)
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="import_mode" id="import_assign" value="import_assign">
                                    <label class="form-check-label" for="import_assign">
                                        <strong>Import & Assign</strong> - Create tokens and assign to users (UPN required)
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="import_mode" id="import_assign_activate" value="import_assign_activate" checked>
                                    <label class="form-check-label" for="import_assign_activate">
                                        <strong>Import, Assign & Activate</strong> - Full process including activation (UPN required)
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Import method tabs -->
                        <ul class="nav nav-tabs import-tabs" role="tablist">
                            <li class="nav-item">
                                <a class="nav-link active" id="file-tab" data-toggle="tab" href="#file-import" role="tab">Upload File</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" id="text-tab" data-toggle="tab" href="#text-import" role="tab">Paste Text</a>
                            </li>
                        </ul>
                        
                        <!-- Tab content -->
                        <div class="tab-content mt-3">
                            <!-- File Upload Tab -->
                            <div class="tab-pane fade show active" id="file-import" role="tabpanel">
                                <form method="POST" enctype="multipart/form-data" id="csvFileForm">
                                    <input type="hidden" name="import_mode" id="file_import_mode" value="import_assign_activate">
                                    <div class="form-group">
                                        <label>Select CSV File:</label>
                                        <input type="file" name="csvFile" accept=".csv,.txt" class="form-control" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Upload & Import</button>
                                </form>
                            </div>
                            
                            <!-- Text Area Tab -->
                            <div class="tab-pane fade" id="text-import" role="tabpanel">
                                <form id="importCSVForm">
                                    <div class="form-group">
                                        <label>CSV Data:</label>
                                        <textarea class="form-control" name="csv_data" rows="10" placeholder="upn,serial number,secret key,timeinterval,manufacturer,model
user@token2.com,1100000000000,JBSWY3DPEHPK3PXP,30,Token2,miniOTP-1" required></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Import</button>
                                </form>
                            </div>
                        </div>
                        
                        <hr>
                        <div class="alert alert-info">
                            <strong>CSV Format Requirements:</strong>
                            <div id="csvFormatInfo">
                                <ul class="mb-0 mt-2">
                                    <li><strong>upn:</strong> <span id="upnRequirement">User's email address (user@domain.com) - Required for assignment modes</span></li>
                                    <li><strong>serial number:</strong> Unique token identifier - Always required</li>
                                    <li><strong>secret key:</strong> Base32 encoded secret (A-Z, 2-7 characters only) - Always required</li>
                                    <li><strong>timeinterval:</strong> Time interval in seconds (usually 30) - Always required</li>
                                    <li><strong>manufacturer:</strong> Token manufacturer name - Always required</li>
                                    <li><strong>model:</strong> Token model name - Always required</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Assign/Activate Modal -->
        <div class="modal fade" id="actionModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 id="actionTitle"></h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body" id="actionBody"></div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button class="btn btn-primary" id="actionBtn"></button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- General Message Modal -->
        <div class="modal fade" id="messageModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 id="messageTitle" class="modal-title"></h5>
                        <button type="button" class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div id="messageIcon" class="text-center mb-3"></div>
                        <p id="messageText"></p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" data-dismiss="modal">OK</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Confirmation Modal -->
        <div class="modal fade" id="confirmModal">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 id="confirmTitle" class="modal-title">Confirm Action</h5>
                        <button type="button" class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="text-center mb-3">
                            <i class="text-warning" style="font-size: 3rem;">⚠️</i>
                        </div>
                        <p id="confirmText"></p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-danger" id="confirmActionBtn">Confirm</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Response Modal -->
        <div class="modal fade" id="responseModal">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 id="responseTitle"></h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <p id="responseMessage"></p>
                        <div id="responseLogSection" style="display: none;">
                            <button class="btn btn-link" data-toggle="collapse" data-target="#responseLog">Show/Hide Log</button>
                            <div id="responseLog" class="collapse log-container"></div>
                        </div>
                    </div>
                    <div class="modal-footer">
                       <!-- <button class="btn btn-secondary" data-dismiss="modal">Close</button> -->
                        <button class="btn btn-primary" onclick="location.reload()">Continue </button>
                    </div>
                </div>
            </div>
        </div>
		
		        <!-- Response Modal Initial -->
        <div class="modal fade" id="responseModal1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 id="responseTitle1"></h5>
                        <button class="close" data-dismiss="modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <p id="responseMessage1"></p>
                        <div id="responseLogSection1" style="display: none;">
                            <button class="btn btn-link" data-toggle="collapse" data-target="#responseLog1">Show/Hide Log</button>
                            <div id="responseLog1" class="collapse log-container"></div>
                        </div>
                    </div>
                    <div class="modal-footer">
                         <button class="btn btn-secondary" data-dismiss="modal">OK</button> 
                      
                    </div>
                </div>
            </div>
        </div>
		
		
        <!-- Tokens Table -->
        <table id="tokensTable" class="table table-striped">
            <thead>
                <tr>
                    <th>Serial</th>
                    <th>Device</th>
					<th>Hash</th>
						<th>Time</th>
                    <th>User</th>
                    <th>Status</th>
                    <th>Seen</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tokens as $t) : ?>
                    <tr data-id="<?= htmlspecialchars($t['id']) ?>">
                        <td><?= htmlspecialchars($t['serialNumber']) ?></td>
                        <td><?= htmlspecialchars($t['manufacturer'] . '/' . $t['model']) ?></td>
						<td><?= htmlspecialchars($t['hashFunction']) ?></td>
							<td><?= htmlspecialchars($t['timeIntervalInSeconds']) ?>s</td>
                        <td><?= isset($t['assignedTo']['displayName']) ? htmlspecialchars($t['assignedTo']['displayName']) : 'Unassigned' ?></td>
                        <td><?= htmlspecialchars($t['status']) ?></td>
                        <td><?= htmlspecialchars($t['lastUsedDateTime'] ?? 'Never') ?></td>
                        <td width=33%>
                            <?php if (!isset($t['assignedTo']['id'])): ?>
                                <button class="btn btn-sm btn-primary" onclick="openAssign('<?= $t['id'] ?>', '<?= $t['serialNumber'] ?>')">Assign</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteToken('<?= $t['id'] ?>')">Delete</button>
                            <?php else: ?>
                                <?php if ($t['status'] !== 'activated'): ?>
                                    <button class="btn btn-sm btn-success" onclick="openActivate('<?= $t['id'] ?>', '<?= $t['serialNumber'] ?>', '<?= htmlspecialchars($t['assignedTo']['displayName'] ?? '', ENT_QUOTES) ?>', '<?= $t['assignedTo']['id'] ?? '' ?>')">Activate</button>
                                <?php endif; ?>
                                <button class="btn btn-sm btn-warning" onclick="unassignToken('<?= $t['id'] ?>', '<?= $t['assignedTo']['id'] ?? '' ?>')">Unassign</button>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div><div style="position: fixed; bottom: 10px; right: 10px; font-size: 14px; color: #555;">
  &copy; Token2
</div>

    <!-- Loading Spinner -->
    <div class="loading-spinner" id="loadingSpinner">
        <div class="spinner"></div>
    </div>
    <script>
        let currentToken = '', currentUser = '';
        
        // Global setting for showing logs
        let showLogsEnabled = <?= json_encode($_SESSION['showLogs']) ?>;
        
        // Completely disable jQuery AJAX to prevent conflicts
        if (typeof $ !== 'undefined') {
            $.fn.post = function() { console.error('jQuery post blocked'); return false; };
            $.post = function() { console.error('jQuery post blocked'); return false; };
            $.get = function() { console.error('jQuery get blocked'); return false; };
            $.ajax = function() { console.error('jQuery ajax blocked'); return false; };
        }
        
        // Modal helper functions
        function showMessage(title, message, type = 'info') {
            const icons = {
                'success': '✅',
                'error': '❌',
                'warning': '⚠️',
                'info': 'ℹ️'
            };
            
            document.getElementById('messageTitle').textContent = title;
            document.getElementById('messageText').textContent = message;
            document.getElementById('messageIcon').innerHTML = `<span style="font-size: 3rem;">${icons[type] || icons.info}</span>`;
            $('#messageModal').modal('show');
        }
        
        function showConfirm(title, message, onConfirm, confirmText = 'Confirm', confirmClass = 'btn-danger') {
            document.getElementById('confirmTitle').textContent = title;
            document.getElementById('confirmText').textContent = message;
            
            const confirmBtn = document.getElementById('confirmActionBtn');
            confirmBtn.textContent = confirmText;
            confirmBtn.className = `btn ${confirmClass}`;
            
            // Remove any existing event listeners
            const newBtn = confirmBtn.cloneNode(true);
            confirmBtn.parentNode.replaceChild(newBtn, confirmBtn);
            
            // Add new event listener
            newBtn.addEventListener('click', function() {
                $('#confirmModal').modal('hide');
                onConfirm();
            });
            
            $('#confirmModal').modal('show');
        }
        
        function validateRequired(fieldName, value, customMessage = null) {
            if (!value || value.trim() === '') {
                showMessage('Validation Error', customMessage || `${fieldName} is required.`, 'error');
                return false;
            }
            return true;
        }
        
        function validateCode(code) {
            if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                showMessage('Validation Error', 'Please enter a valid 6-digit verification code.', 'error');
                return false;
            }
            return true;
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            $('#tokensTable').DataTable({
                pageLength: 25,
                order: [
                    [4, 'desc']
                ]
            });
            
            // Handle import mode changes
            document.querySelectorAll('input[name="import_mode"]').forEach(function(radio) {
                radio.addEventListener('change', function() {
                    let mode = this.value;
                    document.getElementById('file_import_mode').value = mode;
                    updateCSVFormatInfo(mode);
                });
            });
            
            // Initialize CSV format info
            updateCSVFormatInfo('import_assign_activate');
            
            // Only show initial load log for regular page loads (not after form submissions) and if logs are enabled
            <?php if (isset($initialLog) && $_SERVER['REQUEST_METHOD'] !== 'POST') : ?>
                if (showLogsEnabled) {
                    showResponse1(
                        'Initial Load: fetchTokens',
                        'Initial tokens loaded',
                        <?php echo json_encode($initialLog); ?>
                    );
                }
            <?php endif; ?>
            
            // Show import log only for JSON import and if logs are enabled
            <?php if (isset($importLog) && isset($_FILES['importFile'])) : ?>
                if (showLogsEnabled) {
                    showResponse1(
                        'Import Tokens',
                        '<?= $message ?>',
                        <?php echo json_encode($importLog); ?>
                    );
                }
            <?php endif; ?>
            
            // Show CSV import log only for file uploads and textarea submissions and if logs are enabled
            <?php if (isset($csvImportLog) && (isset($_FILES['csvFile']) || isset($_POST['csv_data']))) : ?>
                if (showLogsEnabled) {
                    showResponse1(
                        'Import CSV Tokens',
                        '<?= $csvMessage ?>',
                        <?php echo json_encode($csvImportLog); ?>
                    );
                }
            <?php endif; ?>

            // Handle CSV import form submission (textarea) - VANILLA JS
            document.getElementById('importCSVForm').addEventListener('submit', function(e) {
                e.preventDefault();
                let csvData = this.querySelector('textarea[name="csv_data"]').value;
                let importMode = document.querySelector('input[name="import_mode"]:checked').value;
                
                if (!validateRequired('CSV data', csvData)) {
                    return;
                }
                
                showLoading();
                
                // Use vanilla XMLHttpRequest to avoid jQuery issues
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '?action=import_csv', true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        hideLoading();
                        if (xhr.status === 200) {
                            try {
                                var d = JSON.parse(xhr.responseText);
                                $('#importCSVModal').modal('hide');
                                if (showLogsEnabled) {
                                    showResponse('Import CSV Tokens', 'CSV Tokens imported (Mode: ' + importMode + ')', d.log);
                                } else {
                                    showMessage('Import Successful', 'CSV Tokens imported successfully (Mode: ' + importMode + ')', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                }
                            } catch (e) {
                                showMessage('Import Completed', 'Import completed but response was invalid', 'warning');
                                setTimeout(() => location.reload(), 1500);
                            }
                        } else {
                            if (showLogsEnabled) {
                                showResponse('Error', 'Failed to import CSV tokens', {});
                            } else {
                                showMessage('Import Failed', 'Failed to import CSV tokens', 'error');
                            }
                        }
                    }
                };
                
                var formData = 'csv_data=' + encodeURIComponent(csvData) + 
                              '&import_mode=' + encodeURIComponent(importMode);
                xhr.send(formData);
            });

            // Handle CSV file upload form submission - VANILLA JS
            document.getElementById('csvFileForm').addEventListener('submit', function(e) {
                let fileInput = this.querySelector('input[name="csvFile"]');
                if (!fileInput.files.length) {
                    e.preventDefault();
                    showMessage('File Required', 'Please select a CSV file.', 'error');
                    return;
                }
                showLoading();
                // Let the form submit naturally for file upload
            });
        });
        
        function updateCSVFormatInfo(mode) {
            let upnText = '';
            switch(mode) {
                case 'import_only':
                    upnText = 'User\'s email address (user@domain.com) - Optional for import only mode';
                    break;
                case 'import_assign':
                case 'import_assign_activate':
                    upnText = 'User\'s email address (user@domain.com) - Required for assignment modes';
                    break;
            }
            $('#upnRequirement').text(upnText);
        }

        function showLoading() {
            $('#loadingSpinner').css('display', 'flex');
        }

        function hideLoading() {
            $('#loadingSpinner').hide();
        }

        function openAssign(token, serial) {
            currentToken = token;
            $('#actionTitle').text('Assign Token: ' + serial);
            let html = `
                <div class="form-group" style="position: relative;">
                    <label>Search User:</label>
                    <input type="text" id="userSearch" class="form-control" placeholder="Type to search users..." autocomplete="off">
                    <div id="userResults" class="list-group" style="display: none;"></div>
                    <input type="hidden" id="selectedUserId">
                </div>
            `;
            $('#actionBody').html(html);
            $('#actionBtn').text('Assign').off().click(assignTokenAction);
            $('#actionModal').modal('show');

            // Bind search event
            $('#userSearch').on('input', function() {
                let query = $(this).val().trim();
                if (query.length >= 2) {
                    searchUsers(query);
                } else {
                    $('#userResults').hide().empty();
                }
            });

            // Hide results when clicking outside
            $(document).on('click', function(e) {
                if (!$(e.target).closest('#userSearch, #userResults').length) {
                    $('#userResults').hide();
                }
            });
        }

        function searchUsers(query) {
            // Use vanilla XMLHttpRequest to avoid jQuery issues
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=get_users&query=' + encodeURIComponent(query), true);
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    if (xhr.status === 200) {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            console.log('Search users response:', data); // Debug logging
                            
                            if (data.success && data.users && data.users.length > 0) {
                                let users = data.users;
                                let html = '';
                                users.forEach(u => {
                                    html += `
                                        <a href="#" class="list-group-item list-group-item-action"
                                           data-id="${u.id}"
                                           data-name="${u.displayName || u.userPrincipalName}">
                                            <strong>${u.displayName || u.userPrincipalName}</strong><br>
                                            <small class="text-muted">${u.userPrincipalName}</small>
                                        </a>
                                    `;
                                });
                                $('#userResults').html(html).show();
                            } else if (data.success && data.users && data.users.length === 0) {
                                $('#userResults').html('<div class="list-group-item">No users found</div>').show();
                            } else {
                                // Check for permission errors
                                if (data.permission_error) {
                                    $('#userResults').html(`<div class="list-group-item text-danger">
                                        <strong>Permission Error:</strong><br>
                                        ${data.error}<br>
                                        <small><a href="#" data-toggle="modal" data-target="#settingsModal">Check Settings</a></small>
                                    </div>`).show();
                                } else {
                                    // Show debug information
                                    let errorMsg = 'Failed to load users';
                                    if (data.error) {
                                        errorMsg += ': ' + data.error;
                                    }
                                    if (data.debug) {
                                        console.error('Debug info:', data.debug);
                                        errorMsg += ' (Check browser console for details)';
                                    }
                                    $('#userResults').html(`<div class="list-group-item text-danger">${errorMsg}</div>`).show();
                                }
                            }
                        } catch (e) {
                            console.error('JSON parse error:', e);
                            $('#userResults').html('<div class="list-group-item text-danger">Invalid response from server</div>').show();
                        }
                    } else {
                        console.error('HTTP error:', xhr.status, xhr.responseText);
                        $('#userResults').html(`<div class="list-group-item text-danger">HTTP Error: ${xhr.status}</div>`).show();
                    }
                }
            };
            
            xhr.send();
        }

        $(document).on('click', '#userResults a', function(e) {
            e.preventDefault();
            let userId = $(this).data('id');
            let userName = $(this).data('name');
            $('#userSearch').val(userName);
            $('#selectedUserId').val(userId);
            $('#userResults').hide().empty();
        });

        function openActivate(token, serial, userName, userId) {
            currentToken = token;
            currentUser = userId;
            $('#actionTitle').text('Activate Token: ' + serial + ' for ' + userName);
            $('#actionBody').html(`
                <div class="form-group">
                    <label>Verification Code:</label>
                    <input id="verCode" class="form-control" placeholder="Enter 6-digit code" maxlength="6">
                </div>
                <hr>
                <div class="form-group">
                    <label>Secret Key (optional - for auto-generation):</label>
                    <input id="secretInput" class="form-control" placeholder="Enter secret key to auto-generate code">
                </div>
            `);
            $('#actionBtn').text('Activate').off().click(activateTokenAction);
            $('#actionModal').modal('show');
            
            // Auto-generate code when secret is entered
            $('#secretInput').on('input paste', function() {
                setTimeout(() => {
                    let secret = this.value.trim();
                    if (secret) {
                        totp(secret).then(code => {
                            $('#verCode').val(code);
                        }).catch(err => {
                            console.error('TOTP generation error:', err);
                        });
                    }
                }, 10);
            });
        }

        function assignTokenAction() {
            let uid = document.getElementById('selectedUserId').value;
            
            if (!validateRequired('User selection', uid, 'Please select a user.')) {
                return;
            }
            
            showLoading();
            
            // Use vanilla XMLHttpRequest to avoid jQuery issues
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '?action=assign_token', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    hideLoading();
                    $('#actionModal').modal('hide'); // Properly hide Bootstrap modal
                    
                    if (xhr.status === 200) {
                        try {
                            var d = JSON.parse(xhr.responseText);
                            
                            // Check for credential errors
                            if (d.credential_error) {
                                showMessage('Authentication Error', d.error + '\n\nPlease check your credentials in Settings.', 'error');
                                return;
                            }
                            
                            // Check for permission errors
                            if (d.permission_error) {
                                showMessage('Permission Error', d.permission_error + '\n\nPlease add the required permissions in Azure Portal → App Registrations → API permissions.', 'error');
                                return;
                            }
                            
                            if (showLogsEnabled) {
                                showResponse('Assign Token', d.success ? 'Token assigned successfully!' : 'Failed to assign token', d.log);
                            } else {
                                showMessage('Assignment ' + (d.success ? 'Successful' : 'Failed'), 
                                          d.success ? 'Token assigned successfully!' : 'Failed to assign token', 
                                          d.success ? 'success' : 'error');
                                if (d.success) setTimeout(() => location.reload(), 1500);
                            }
                        } catch (e) {
                            showMessage('Assignment Completed', 'Assignment completed but response was invalid', 'warning');
                            setTimeout(() => location.reload(), 1500);
                        }
                    } else {
                        if (showLogsEnabled) {
                            showResponse('Error', 'Failed to assign token', {});
                        } else {
                            showMessage('Assignment Failed', 'Failed to assign token', 'error');
                        }
                    }
                }
            };
            
            var formData = 'token_id=' + encodeURIComponent(currentToken) + 
                          '&user_id=' + encodeURIComponent(uid);
            xhr.send(formData);
        }

        function activateTokenAction() {
            let code = document.getElementById('verCode').value;
            
            if (!validateCode(code)) {
                return;
            }
            
            showLoading();
            
            // Use vanilla XMLHttpRequest to avoid jQuery issues
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '?action=activate_token', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    hideLoading();
                    $('#actionModal').modal('hide'); // Properly hide Bootstrap modal
                    
                    if (xhr.status === 200) {
                        try {
                            var d = JSON.parse(xhr.responseText);
                            
                            // Check for credential errors
                            if (d.credential_error) {
                                showMessage('Authentication Error', d.error + '\n\nPlease check your credentials in Settings.', 'error');
                                return;
                            }
                            
                            // Check for permission errors
                            if (d.permission_error) {
                                showMessage('Permission Error', d.permission_error + '\n\nPlease add the required permissions in Azure Portal → App Registrations → API permissions.', 'error');
                                return;
                            }
                            
                            if (showLogsEnabled) {
                                showResponse('Activate Token', d.success ? 'Token activated successfully!' : 'Failed to activate token', d.log);
                            } else {
                                showMessage('Activation ' + (d.success ? 'Successful' : 'Failed'), 
                                          d.success ? 'Token activated successfully!' : 'Failed to activate token', 
                                          d.success ? 'success' : 'error');
                                if (d.success) setTimeout(() => location.reload(), 1500);
                            }
                        } catch (e) {
                            showMessage('Activation Completed', 'Activation completed but response was invalid', 'warning');
                            setTimeout(() => location.reload(), 1500);
                        }
                    } else {
                        if (showLogsEnabled) {
                            showResponse('Error', 'Failed to activate token', {});
                        } else {
                            showMessage('Activation Failed', 'Failed to activate token', 'error');
                        }
                    }
                }
            };
            
            var formData = 'token_id=' + encodeURIComponent(currentToken) + 
                          '&user_id=' + encodeURIComponent(currentUser) + 
                          '&verification_code=' + encodeURIComponent(code);
            xhr.send(formData);
        }

        function unassignToken(token, user) {
            showConfirm(
                'Unassign Token',
                'Are you sure you want to unassign this token?',
                function() {
                    showLoading();
                    
                    // Use vanilla XMLHttpRequest to avoid jQuery issues
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', '?action=unassign_token', true);
                    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                    
                    xhr.onreadystatechange = function() {
                        if (xhr.readyState === 4) {
                            hideLoading();
                            
                            if (xhr.status === 200) {
                                try {
                                    var d = JSON.parse(xhr.responseText);
                                    
                                    // Check for credential errors
                                    if (d.credential_error) {
                                        showMessage('Authentication Error', d.error + '\n\nPlease check your credentials in Settings.', 'error');
                                        return;
                                    }
                                    
                                    // Check for permission errors
                                    if (d.permission_error) {
                                        showMessage('Permission Error', d.permission_error + '\n\nPlease add the required permissions in Azure Portal → App Registrations → API permissions.', 'error');
                                        return;
                                    }
                                    
                                    if (showLogsEnabled) {
                                        showResponse('Unassign Token', d.success ? 'Token unassigned successfully!' : 'Failed to unassign token', d.log);
                                    } else {
                                        showMessage('Unassignment ' + (d.success ? 'Successful' : 'Failed'), 
                                                  d.success ? 'Token unassigned successfully!' : 'Failed to unassign token', 
                                                  d.success ? 'success' : 'error');
                                        if (d.success) setTimeout(() => location.reload(), 1500);
                                    }
                                } catch (e) {
                                    showMessage('Unassignment Completed', 'Unassignment completed but response was invalid', 'warning');
                                    setTimeout(() => location.reload(), 1500);
                                }
                            } else {
                                if (showLogsEnabled) {
                                    showResponse('Error', 'Failed to unassign token', {});
                                } else {
                                    showMessage('Unassignment Failed', 'Failed to unassign token', 'error');
                                }
                            }
                        }
                    };
                    
                    var formData = 'token_id=' + encodeURIComponent(token) + 
                                  '&user_id=' + encodeURIComponent(user);
                    xhr.send(formData);
                },
                'Unassign',
                'btn-warning'
            );
        }

        function deleteToken(token) {
            showConfirm(
                'Delete Token',
                'Are you sure you want to delete this token? This action cannot be undone.',
                function() {
                    showLoading();
                    
                    // Use vanilla XMLHttpRequest to avoid jQuery issues
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', '?action=delete_token', true);
                    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                    
                    xhr.onreadystatechange = function() {
                        if (xhr.readyState === 4) {
                            hideLoading();
                            
                            if (xhr.status === 200) {
                                try {
                                    var d = JSON.parse(xhr.responseText);
                                    
                                    // Check for credential errors
                                    if (d.credential_error) {
                                        showMessage('Authentication Error', d.error + '\n\nPlease check your credentials in Settings.', 'error');
                                        return;
                                    }
                                    
                                    // Check for permission errors
                                    if (d.permission_error) {
                                        showMessage('Permission Error', d.permission_error + '\n\nPlease add the required permissions in Azure Portal → App Registrations → API permissions.', 'error');
                                        return;
                                    }
                                    
                                    if (showLogsEnabled) {
                                        showResponse('Delete Token', d.success ? 'Token deleted successfully!' : 'Failed to delete token', d.log);
                                    } else {
                                        showMessage('Deletion ' + (d.success ? 'Successful' : 'Failed'), 
                                                  d.success ? 'Token deleted successfully!' : 'Failed to delete token', 
                                                  d.success ? 'success' : 'error');
                                        if (d.success) setTimeout(() => location.reload(), 1500);
                                    }
                                } catch (e) {
                                    showMessage('Deletion Completed', 'Deletion completed but response was invalid', 'warning');
                                    setTimeout(() => location.reload(), 1500);
                                }
                            } else {
                                if (showLogsEnabled) {
                                    showResponse('Error', 'Failed to delete token', {});
                                } else {
                                    showMessage('Deletion Failed', 'Failed to delete token', 'error');
                                }
                            }
                        }
                    };
                    
                    var formData = 'token_id=' + encodeURIComponent(token);
                    xhr.send(formData);
                },
                'Delete',
                'btn-danger'
            );
        }

        function showResponse(title, message, log) {
            $('#responseTitle').text(title);
            $('#responseMessage').text(message);
            if (showLogsEnabled && log) {
                $('#responseLog').text(JSON.stringify(log, null, 2));
                $('#responseLogSection').show();
            } else {
                $('#responseLogSection').hide();
            }
            $('#responseModal').modal('show');
        }
		
        function showResponse1(title, message, log) {
            $('#responseTitle1').text(title);
            $('#responseMessage1').text(message);
            if (showLogsEnabled && log) {
                $('#responseLog1').text(JSON.stringify(log, null, 2));
                $('#responseLogSection1').show();
            } else {
                $('#responseLogSection1').hide();
            }
            $('#responseModal1').modal('show');
        }

        function totp(secret, timeStep = 30) {
            // Auto-detect hash algorithm by secret length
            const algorithm = secret.length <= 32 ? 'SHA-1' : 'SHA-256';

            // Base32 decode
            const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let bits = '', bytes = [];

            for (let char of secret.toUpperCase()) {
                if (base32Chars.indexOf(char) === -1) {
                    throw new Error('Invalid Base32 character: ' + char);
                }
                bits += base32Chars.indexOf(char).toString(2).padStart(5, '0');
            }

            for (let i = 0; i < bits.length; i += 8) {
                if (bits.length - i >= 8) {
                    bytes.push(parseInt(bits.substr(i, 8), 2));
                }
            }

            // Time counter (30-second window)
            const counter = Math.floor(Date.now() / 1000 / timeStep);
            const counterBytes = new ArrayBuffer(8);
            new DataView(counterBytes).setBigUint64(0, BigInt(counter));

            // HMAC calculation
            return crypto.subtle.importKey('raw', new Uint8Array(bytes), {name: 'HMAC', hash: algorithm}, false, ['sign'])
                .then(key => crypto.subtle.sign('HMAC', key, counterBytes))
                .then(signature => {
                    const hash = new Uint8Array(signature);
                    const offset = hash[hash.length - 1] & 0x0f;
                    const code = ((hash[offset] & 0x7f) << 24) |
                                 ((hash[offset + 1] & 0xff) << 16) |
                                 ((hash[offset + 2] & 0xff) << 8) |
                                 (hash[offset + 3] & 0xff);
                    return (code % 1000000).toString().padStart(6, '0');
                });
        }
    </script>
</body>
</html>
