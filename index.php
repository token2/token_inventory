
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

// Get Access Token
$accessToken = getAccessToken($tenantId, $clientId, $clientSecret);
if (!$accessToken) {
    die('Failed to authenticate with Microsoft Graph.');
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

       
        <table id="tokensTable" class="table table-striped">
            <thead class="thead-dark">
                <tr>
                    <th>Serial Number</th>
                    <th>Device</th>
                    <th>User ID</th>
                    <th>Status</th>
                    <th>Last Updated</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tokens as $token): ?>
                    <tr>
                        <td><?= htmlspecialchars($token['serialNumber']) ?></td>
                        <td><?= htmlspecialchars($token['manufacturer']) ?> / <?= htmlspecialchars($token['model']) ?></td>
                        <td><?= htmlspecialchars($token['assignedTo']['displayName'] ?? 'Unassigned') ?></td>
                        <td><?= htmlspecialchars($token['status']) ?></td>
                        <td><?= htmlspecialchars($token['lastUsedDateTime'] ?? 'Never') ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <script>
        $(document).ready(function() {
            $('#tokensTable').DataTable();
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
