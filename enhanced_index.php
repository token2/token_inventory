<?php

// Configuration
$tenantId = 'xxx';
$clientId = 'xxx';
$clientSecret = 'xx';


$valid_username = 'admin'; // Set your username
$valid_password = 'P@ssword1'; // Set your password
 
 
error_reporting(E_ALL);
ini_set('display_errors', 1);

 

session_start();

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check if the user is already logged in
if (!isset($_SESSION['logged_in'])) {
    // Check if form was submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        // Validate credentials
        if ($username === $valid_username && $password === $valid_password) {
            $_SESSION['logged_in'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']); // Redirect to avoid form resubmission
            exit;
        } else {
            $error_message = 'Invalid username or password';
        }
    }

    // Show login form if not authenticated
    echo '<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
        <link rel="stylesheet" href="assets/bootstrap.min.css">
    </head>
    <body>
        <div class="container mt-4" style="max-width:600px">
            <h2>Please Log In</h2><hr>
            <form method="POST">  
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                </div>
                ' . (isset($error_message) ? '<p class="text-danger">' . htmlspecialchars($error_message) . '</p>' : '') . '
                <button type="submit" class="btn btn-primary">Login</button>  
            </form>
        </div>
    </body>
    </html>';
    exit;
}

// Function to get an access token
function getAccessToken($tenantId, $clientId, $clientSecret) {
    $url = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token";
    $data = [
        'grant_type'    => 'client_credentials',
        'client_id'     => $clientId,
        'client_secret' => $clientSecret,
        'scope'         => 'https://graph.microsoft.com/.default',
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    $response = curl_exec($ch);
    curl_close($ch);

    $response = json_decode($response, true);
    return $response['access_token'] ?? null;
}

// Function to fetch hardware tokens
function fetchHardwareTokens($accessToken) {
    $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);

    $responseData = json_decode($response, true);

    // Debugging: Save raw API response to debug.log
    file_put_contents('debug.log', print_r($responseData, true));

    return $responseData['value'] ?? [];
}

// Function to import tokens via PATCH
function importTokens($accessToken, $importData) {
    $url = "https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($importData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    return json_decode($response, true);
}

// NEW FUNCTION: Simple user fetch with detailed debugging
function getUsers($accessToken) {
    // Start with the exact same query that works in Graph Explorer
    $url = "https://graph.microsoft.com/v1.0/users?\$top=5";
    
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
        "User-Agent: Token2-PHP-Client/1.0"
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    // Detailed logging
    error_log("=== USER API DEBUG ===");
    error_log("URL: $url");
    error_log("HTTP Code: $httpCode");
    error_log("CURL Error: $error");
    error_log("Response Length: " . strlen($response));
    error_log("Response (first 500 chars): " . substr($response, 0, 500));
    error_log("=== END DEBUG ===");

    if ($error) {
        error_log("CURL Error getting users: $error");
        return ['error' => "Connection error: $error"];
    }
    
    if ($httpCode !== 200) {
        error_log("HTTP Error getting users: $httpCode - Response: $response");
        return ['error' => "HTTP $httpCode: " . substr($response, 0, 200)];
    }

    $responseData = json_decode($response, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON decode error: " . json_last_error_msg());
        return ['error' => "JSON decode error: " . json_last_error_msg()];
    }
    
    if (!isset($responseData['value'])) {
        error_log("No 'value' key in response: " . print_r($responseData, true));
        return ['error' => "Invalid response format"];
    }

    $users = $responseData['value'];
    error_log("Successfully fetched " . count($users) . " users");
    
    return $users;
}

// NEW FUNCTION: Activate token
function activateToken($accessToken, $userId, $tokenId, $verificationCode) {
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods/$tokenId/activate";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];
    
    $data = ["verificationCode" => $verificationCode];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ($httpCode === 204 || $httpCode === 200);
}

// NEW FUNCTION: Assign token
function assignToken($accessToken, $userId, $tokenId) {
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];
    
    $data = ["device" => ["id" => $tokenId]];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ($httpCode === 201 || $httpCode === 200);
}

// Get Access Token
$accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
if (!$accessToken) {
    die('Failed to authenticate with Microsoft Graph. Check your credentials.');
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    try {
        switch ($_GET['action']) {
            case 'get_users':
                $users = getUsers($accessToken);
                if (empty($users)) {
                    echo json_encode(['success' => false, 'error' => 'No users found or permission error']);
                } else {
                    echo json_encode(['success' => true, 'users' => $users]);
                }
                break;
                
            case 'activate_token':
                $userId = $_POST['user_id'] ?? '';
                $tokenId = $_POST['token_id'] ?? '';
                $verificationCode = $_POST['verification_code'] ?? '';
                
                if ($userId && $tokenId && $verificationCode) {
                    $result = activateToken($accessToken, $userId, $tokenId, $verificationCode);
                    echo json_encode(['success' => $result]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Missing parameters']);
                }
                break;
                
            case 'assign_token':
                $userId = $_POST['user_id'] ?? '';
                $tokenId = $_POST['token_id'] ?? '';
                
                if ($userId && $tokenId) {
                    $result = assignToken($accessToken, $userId, $tokenId);
                    echo json_encode(['success' => $result]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Missing parameters']);
                }
                break;
                
            default:
                echo json_encode(['success' => false, 'error' => 'Invalid action']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// Handle Import Action
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['importFile'])) {
    $fileContent = file_get_contents($_FILES['importFile']['tmp_name']);
    $importData = json_decode($fileContent, true);

    if ($importData) {
        $result = importTokens($accessToken, $importData);
        $message = $result ? 'Tokens successfully imported!' : 'Failed to import tokens.';
    } else {
        $message = 'Invalid JSON file.';
    }
}

// Fetch Hardware Tokens
$tokens = fetchHardwareTokens($accessToken);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hardware Token Management</title>
    <link rel="stylesheet" href="assets/bootstrap.min.css">
    <script src="assets/jquery-3.6.0.min.js"></script>
    <script src="assets/jquery.dataTables.min.js"></script>
    <script src="assets/dataTables.bootstrap4.min.js"></script>
    <link rel="stylesheet" href="assets/dataTables.bootstrap4.min.css">
    <script src="assets/bootstrap.min.js"></script>
    <style>
        .message { color: green; font-weight: bold; margin-bottom: 20px; }
        .status-available { color: #28a745; }
        .status-assigned { color: #007bff; }
        .status-activated { color: #17a2b8; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="float-right">
            <!-- Import Button -->
            <button type="button" class="btn btn-primary mb-3 mx-1" data-toggle="modal" data-target="#importModal">
                Import Tokens
            </button>
            
            <a href="?logout" class="btn btn-secondary mb-3">
                Log Out 
            </a>
        </div>
        
        <h5>Entra ID - Hardware token inventory portal</h5>
        <?php if ($message): ?>
            <p class="message"><?= htmlspecialchars($message) ?></p>
        <?php endif; ?>
        
        <br style="clear:both">

        <!-- Import Modal -->
        <div class="modal fade" id="importModal" tabindex="-1" role="dialog">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Import Tokens</h5>
                        <button type="button" class="close" data-dismiss="modal">
                            <span>&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <form method="POST" enctype="multipart/form-data">
                            <div class="form-group">
                                <label for="importFile">Upload JSON File:</label>
                                <input type="file" id="importFile" name="importFile" accept="application/json" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Upload</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Assign Modal -->
        <div class="modal fade" id="assignModal" tabindex="-1" role="dialog">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Assign Token</h5>
                        <button type="button" class="close" data-dismiss="modal">
                            <span>&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label>Token:</label>
                            <input type="text" id="tokenSerial" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label>Select User:</label>
                            <select id="userSelect" class="form-control">
                                <option value="">Loading users...</option>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="assignTokenAction()">Assign</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Activate Modal -->
        <div class="modal fade" id="activateModal" tabindex="-1" role="dialog">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Activate Token</h5>
                        <button type="button" class="close" data-dismiss="modal">
                            <span>&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label>Token:</label>
                            <input type="text" id="activateTokenSerial" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label>User:</label>
                            <input type="text" id="activateUser" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label>Verification Code:</label>
                            <input type="text" id="verificationCode" class="form-control" placeholder="Enter 6-digit code" maxlength="6">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-success" onclick="activateTokenAction()">Activate</button>
                    </div>
                </div>
            </div>
        </div>

        <table id="tokensTable" class="table table-striped">
            <thead class="thead-dark">
                <tr>
                    <th>Serial Number</th>
                    <th>Device</th>
                    <th>Assigned User</th>
                    <th>Status</th>
                    <th>Last Updated</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tokens as $token): ?>
                    <tr data-token-id="<?= htmlspecialchars($token['id']) ?>">
                        <td><?= htmlspecialchars($token['serialNumber']) ?></td>
                        <td><?= htmlspecialchars($token['manufacturer']) ?> / <?= htmlspecialchars($token['model']) ?></td>
                        <td>
                            <?php if (isset($token['assignedTo']) && $token['assignedTo']): ?>
                                <span data-user-id="<?= htmlspecialchars($token['assignedTo']['id'] ?? '') ?>">
                                    <?= htmlspecialchars($token['assignedTo']['displayName']) ?>
                                </span>
                            <?php else: ?>
                                <span class="text-muted">Unassigned</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="status-<?= htmlspecialchars($token['status']) ?>">
                                <?= htmlspecialchars(ucfirst($token['status'])) ?>
                            </span>
                        </td>
                        <td><?= htmlspecialchars($token['lastUsedDateTime'] ?? 'Never') ?></td>
                        <td>
                            <?php if ($token['status'] === 'available'): ?>
                                <button class="btn btn-sm btn-outline-primary" onclick="openAssignModal('<?= htmlspecialchars($token['id']) ?>', '<?= htmlspecialchars($token['serialNumber']) ?>')">
                                    Assign
                                </button>
                            <?php elseif ($token['status'] === 'assigned'): ?>
                                <button class="btn btn-sm btn-outline-success" onclick="openActivateModal('<?= htmlspecialchars($token['id']) ?>', '<?= htmlspecialchars($token['serialNumber']) ?>', '<?= htmlspecialchars($token['assignedTo']['displayName'] ?? '') ?>', '<?= htmlspecialchars($token['assignedTo']['id'] ?? '') ?>')">
                                    Activate
                                </button>
                            <?php elseif ($token['status'] === 'activated'): ?>
                                <span class="badge badge-success">Active</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <script>
        let currentTokenId = '';
        let currentUserId = '';

        $(document).ready(function() {
            $('#tokensTable').DataTable({
                "pageLength": 25,
                "order": [[ 4, "desc" ]]
            });
        });

        function loadUsers() {
            console.log('🔍 Loading users...');
            
            $.get('?action=get_users')
                .done(function(data) {
                    console.log('📦 Users API response:', data);
                    const select = $('#userSelect');
                    select.empty();
                    
                    if (data.success && data.users && data.users.length > 0) {
                        select.append('<option value="">Select a user...</option>');
                        
                        data.users.forEach(function(user) {
                            // Handle cases where displayName might be missing
                            const displayName = user.displayName || user.userPrincipalName || 'Unknown User';
                            const userPrincipal = user.userPrincipalName || user.mail || 'No UPN';
                            
                            select.append(`<option value="${user.id}" title="${userPrincipal}">${displayName} (${userPrincipal})</option>`);
                        });
                        
                        console.log(`✅ Successfully loaded ${data.users.length} users`);
                        
                        // Log first user for debugging
                        if (data.users[0]) {
                            console.log('👤 First user sample:', {
                                id: data.users[0].id,
                                displayName: data.users[0].displayName,
                                userPrincipalName: data.users[0].userPrincipalName
                            });
                        }
                        
                    } else {
                        console.warn('⚠️ No users found or API error:', data);
                        
                        let errorMsg = 'No users found';
                        if (data.error) {
                            errorMsg = data.error;
                            console.error('❌ Detailed error:', data);
                        }
                        
                        select.append(`<option value="" style="color: red;">${errorMsg}</option>`);
                    }
                })
                .fail(function(xhr, status, error) {
                    console.error('❌ AJAX request failed:');
                    console.error('Status:', status);
                    console.error('Error:', error);
                    console.error('Response:', xhr.responseText);
                    console.error('HTTP Status:', xhr.status);
                    
                    const select = $('#userSelect');
                    select.empty();
                    select.append('<option value="" style="color: red;">Connection Error</option>');
                    
                    // Show detailed error
                    alert(`Failed to load users!\n\nStatus: ${status}\nError: ${error}\nHTTP: ${xhr.status}\n\nCheck browser console for details.`);
                });
        }

        function openAssignModal(tokenId, serialNumber) {
            currentTokenId = tokenId;
            $('#tokenSerial').val(serialNumber);
            $('#assignModal').modal('show');
            loadUsers();
        }

        function openActivateModal(tokenId, serialNumber, userName, userId) {
            currentTokenId = tokenId;
            currentUserId = userId;
            $('#activateTokenSerial').val(serialNumber);
            $('#activateUser').val(userName);
            $('#verificationCode').val('');
            $('#activateModal').modal('show');
        }

        function assignTokenAction() {
            const userId = $('#userSelect').val();
            if (!userId) {
                alert('Please select a user');
                return;
            }

            $.post('?action=assign_token', {
                token_id: currentTokenId,
                user_id: userId
            })
            .done(function(data) {
                if (data.success) {
                    alert('Token assigned successfully!');
                    location.reload();
                } else {
                    alert('Failed to assign token: ' + (data.error || 'Unknown error'));
                }
            })
            .fail(function() {
                alert('Error occurred while assigning token');
            })
            .always(function() {
                $('#assignModal').modal('hide');
            });
        }

        function activateTokenAction() {
            const code = $('#verificationCode').val();
            if (!code || code.length !== 6) {
                alert('Please enter a valid 6-digit code');
                return;
            }

            $.post('?action=activate_token', {
                token_id: currentTokenId,
                user_id: currentUserId,
                verification_code: code
            })
            .done(function(data) {
                if (data.success) {
                    alert('Token activated successfully!');
                    location.reload();
                } else {
                    alert('Failed to activate token: ' + (data.error || 'Unknown error'));
                }
            })
            .fail(function() {
                alert('Error occurred while activating token');
            })
            .always(function() {
                $('#activateModal').modal('hide');
            });
        }
    </script>

    <br><br><hr>
    <!-- Footer -->
    <footer class="text-center text-lg-start bg-body-tertiary text-muted container mt-4">
        <div class="text-center p-4" style="background-color: rgba(0, 0, 0, 0.05);">
            Created by 
            <a class="text-reset fw-bold" href="https://token2.swiss/">Token2 Sarl </a>
        </div>
    </footer>
</body>
</html>
