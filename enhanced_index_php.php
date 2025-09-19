<?php

// Configuration
$tenantId = 'xxx';
$clientId = 'xxx';
$clientSecret = 'xx';

$valid_username = 'admin'; // Set your username
$valid_password = 'P@ssword1'; // Set your password

 
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

// NEW FUNCTION: Activate a token for a specific user
function activateToken($accessToken, $userId, $tokenId, $verificationCode) {
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods/$tokenId/activate";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];
    
    $data = [
        "verificationCode" => $verificationCode
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $responseData = json_decode($response, true);
    
    return [
        'success' => $httpCode === 204 || $httpCode === 200,
        'httpCode' => $httpCode,
        'response' => $responseData
    ];
}

// NEW FUNCTION: Assign a token to a user
function assignToken($accessToken, $userId, $tokenId) {
    $url = "https://graph.microsoft.com/beta/users/$userId/authentication/hardwareOathMethods";
    $headers = [
        "Authorization: Bearer $accessToken",
        "Content-Type: application/json",
    ];
    
    $data = [
        "device" => [
            "id" => $tokenId
        ]
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return [
        'success' => $httpCode === 201 || $httpCode === 200,
        'httpCode' => $httpCode,
        'response' => json_decode($response, true)
    ];
}

// NEW FUNCTION: Get users for assignment dropdown
function getUsers($accessToken, $search = '') {
    $url = "https://graph.microsoft.com/v1.0/users";
    if ($search) {
        $url .= "?\$filter=startswith(displayName,'$search') or startswith(userPrincipalName,'$search')&\$top=20";
    } else {
        $url .= "?\$top=50";
    }
    
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
    return $responseData['value'] ?? [];
}

// Get Access Token
$accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
if (!$accessToken) {
    die('Failed to authenticate with Microsoft Graph.');
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'get_users':
            $search = $_GET['search'] ?? '';
            $users = getUsers($accessToken, $search);
            echo json_encode(['users' => $users]);
            break;
            
        case 'activate_token':
            $userId = $_POST['user_id'] ?? '';
            $tokenId = $_POST['token_id'] ?? '';
            $verificationCode = $_POST['verification_code'] ?? '';
            
            if ($userId && $tokenId && $verificationCode) {
                $result = activateToken($accessToken, $userId, $tokenId, $verificationCode);
                echo json_encode($result);
            } else {
                echo json_encode(['success' => false, 'error' => 'Missing required parameters']);
            }
            break;
            
        case 'assign_token':
            $userId = $_POST['user_id'] ?? '';
            $tokenId = $_POST['token_id'] ?? '';
            
            if ($userId && $tokenId) {
                $result = assignToken($accessToken, $userId, $tokenId);
                echo json_encode($result);
            } else {
                echo json_encode(['success' => false, 'error' => 'Missing required parameters']);
            }
            break;
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
        .activation-timer { 
            font-weight: bold; 
            color: #dc3545;
            font-size: 0.9em;
        }
        .user-select { 
            width: 200px; 
            max-width: 200px;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
<div class="float-right"	
	   
		
		
		
	<!-- Import Button -->
        <button type="button" class="btn btn-primary mb-3   mx-1 " data-toggle="modal" data-target="#importModal">
            import tokens
        </button>
		
		<a  href=?logout class="btn btn-secondary mb-3   "  >
            log out 
        </a>
		
	</div>	
		
		
        <h5>Entra ID - Hardware token inventory portal</h5>
        <?php if ($message): ?>
            <p class="message"><?= htmlspecialchars($message) ?></p>
        <?php endif; ?>
        
       
		<br style="clear:both">
		

        <!-- Import Modal -->
        <div class="modal fade" id="importModal" tabindex="-1" role="dialog" aria-labelledby="importModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="importModalLabel">Import Tokens</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
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

        <!-- Assign Token Modal -->
        <div class="modal fade" id="assignModal" tabindex="-1" role="dialog" aria-labelledby="assignModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="assignModalLabel">Assign Token</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="tokenSerial">Token Serial:</label>
                            <input type="text" id="tokenSerial" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label for="userSelect">Select User:</label>
                            <select id="userSelect" class="form-control user-select">
                                <option value="">Loading users...</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="userSearch">Or search for user:</label>
                            <input type="text" id="userSearch" class="form-control" placeholder="Type to search users...">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="assignToken()">Assign Token</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Activate Token Modal -->
        <div class="modal fade" id="activateModal" tabindex="-1" role="dialog" aria-labelledby="activateModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="activateModalLabel">Activate Token</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="activateTokenSerial">Token Serial:</label>
                            <input type="text" id="activateTokenSerial" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label for="activateUser">Assigned User:</label>
                            <input type="text" id="activateUser" class="form-control" readonly>
                        </div>
                        <div class="form-group">
                            <label for="verificationCode">Verification Code from Token:</label>
                            <input type="text" id="verificationCode" class="form-control" placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{6}">
                            <small class="form-text text-muted">
                                Enter the current 6-digit code displayed on the hardware token.
                                <span id="activationTimer" class="activation-timer"></span>
                            </small>
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
                                <span title="<?= htmlspecialchars($token['assignedTo']['id'] ?? '') ?>">
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
                                <button class="btn btn-sm btn-outline-primary" 
                                        onclick="openAssignModal('<?= htmlspecialchars($token['id']) ?>', '<?= htmlspecialchars($token['serialNumber']) ?>')">
                                    Assign
                                </button>
                            <?php elseif ($token['status'] === 'assigned'): ?>
                                <button class="btn btn-sm btn-outline-success" 
                                        onclick="openActivateModal('<?= htmlspecialchars($token['id']) ?>', 
                                                                    '<?= htmlspecialchars($token['serialNumber']) ?>', 
                                                                    '<?= htmlspecialchars($token['assignedTo']['displayName'] ?? '') ?>',
                                                                    '<?= htmlspecialchars($token['assignedTo']['id'] ?? '') ?>')">
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
        let activationTimer;

        $(document).ready(function() {
            $('#tokensTable').DataTable({
                "pageLength": 25,
                "order": [[ 4, "desc" ]]
            });
            
            // Load users on page load
            loadUsers();
            
            // User search functionality
            $('#userSearch').on('input', function() {
                const search = $(this).val();
                if (search.length >= 2) {
                    loadUsers(search);
                } else if (search.length === 0) {
                    loadUsers();
                }
            });
        });

        function loadUsers(search = '') {
            $.get('?action=get_users&search=' + encodeURIComponent(search))
                .done(function(data) {
                    const select = $('#userSelect');
                    select.empty();
                    select.append('<option value="">Select a user...</option>');
                    
                    if (data.users) {
                        data.users.forEach(function(user) {
                            select.append(`<option value="${user.id}">${user.displayName} (${user.userPrincipalName})</option>`);
                        });
                    }
                })
                .fail(function() {
                    $('#userSelect').html('<option value="">Error loading users</option>');
                });
        }

        function openAssignModal(tokenId, serialNumber) {
            currentTokenId = tokenId;
            $('#tokenSerial').val(serialNumber);
            $('#userSelect').val('');
            $('#userSearch').val('');
            $('#assignModal').modal('show');
        }

        function openActivateModal(tokenId, serialNumber, userName, userId) {
            currentTokenId = tokenId;
            currentUserId = userId;
            $('#activateTokenSerial').val(serialNumber);
            $('#activateUser').val(userName);
            $('#verificationCode').val('');
            $('#activateModal').modal('show');
            
            // Start countdown timer
            startActivationTimer();
        }

        function startActivationTimer() {
            let timeLeft = 30; // 30 seconds countdown for TOTP
            const timer = $('#activationTimer');
            
            activationTimer = setInterval(function() {
                timer.text(`(Code expires in ${timeLeft}s)`);
                timeLeft--;
                
                if (timeLeft < 0) {
                    clearInterval(activationTimer);
                    timer.text('(Code may have expired - get new code)');
                }
            }, 1000);
        }

        function assignToken() {
            const userId = $('#userSelect').val();
            
            if (!userId) {
                alert('Please select a user');
                return;
            }

            const button = $('#assignModal .btn-primary');
            button.prop('disabled', true).text('Assigning...');
            
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
                button.prop('disabled', false).text('Assign Token');
                $('#assignModal').modal('hide');
            });
        }

        function activateTokenAction() {
            const verificationCode = $('#verificationCode').val();
            
            if (!verificationCode || verificationCode.length !== 6) {
                alert('Please enter a valid 6-digit verification code');
                return;
            }

            const button = $('#activateModal .btn-success');
            button.prop('disabled', true).text('Activating...');
            
            // Clear timer
            if (activationTimer) {
                clearInterval(activationTimer);
            }
            
            $.post('?action=activate_token', {
                token_id: currentTokenId,
                user_id: currentUserId,
                verification_code: verificationCode
            })
            .done(function(data) {
                if (data.success) {
                    alert('Token activated successfully!');
                    location.reload();
                } else {
                    alert('Failed to activate token. Please verify the code is correct and try again.');
                }
            })
            .fail(function() {
                alert('Error occurred while activating token');
            })
            .always(function() {
                button.prop('disabled', false).text('Activate');
                $('#activateModal').modal('hide');
            });
        }

        // Close modal cleanup
        $('#activateModal').on('hidden.bs.modal', function() {
            if (activationTimer) {
                clearInterval(activationTimer);
            }
        });
    </script>


<br><br><hr>
<!-- Footer -->
<footer class="text-center text-lg-start bg-body-tertiary text-muted container mt-4">
   

  <!-- Copyright -->
  <div class="text-center p-4" style="background-color: rgba(0, 0, 0, 0.05);">
    Created by 
    <a class="text-reset fw-bold" href="https://token2.swiss/">Token2 Sarl </a>
  </div>
  <!-- Copyright -->
</footer>

</body>
</html>