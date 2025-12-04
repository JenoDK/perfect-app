<?php
// SECURITY VULNERABILITY: Hardcoded API keys and passwords
$api_key = "sk_live_51H3ll0W0rld1234567890abcdef";
$db_password = "SuperSecretPassword123!";
$aws_access_key = "AKIAIOSFODNN7EXAMPLE";
$aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SECURITY VULNERABILITY: Command injection (existing - unsanitized user input in shell command)
if (isset($_GET['ns_dig']) && !empty($_GET['ns_dig'])) {
$ns_dig = explode(',', $_GET['ns_dig']);
} else {
$ns_dig = ['8.8.8.8', '8.8.4.4'];
}
$domains = ['domain' => 'example.com'];
$first = `dig @$ns_dig[0] -t ns $domains[domain]`;

// SECURITY VULNERABILITY: XSS - unescaped user input in HTML output
$user_input = $_GET['name'] ?? '';
echo "<pre>$first</pre>";
echo "<h1>Welcome, " . $user_input . "!</h1>"; // XSS vulnerability

// SECURITY VULNERABILITY: SQL injection - unparameterized query
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$conn = new mysqli("localhost", "root", $db_password, "users");
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query); // SQL injection vulnerability

// SECURITY VULNERABILITY: Logging sensitive user credentials
error_log("User login attempt: username=$username, password=$password");
file_put_contents('app.log', "Login: $username with password $password\n", FILE_APPEND);

// SECURITY VULNERABILITY: Exposed credentials in headers
header("X-API-Key: $api_key");
header("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");