<?php
/**
 * Type Juggling Challenge
 * Port: 8014 (via Docker)
 *
 * A PHP login that uses loose comparison (==) to check the password
 * against its MD5 hash. Find an input whose MD5 starts with "0e"
 * followed by only digits — PHP treats both sides as float 0.
 */

$flag = trim(file_get_contents("flag.txt"));

// The admin password hash (MD5 of a real password)
// MD5("securepassword") = "ef775988943825d2871e1cfa75473ec0"
$stored_hash = "0e462097431906509019562988736854";
// This is MD5("240610708") which starts with 0e and has only digits after

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $password = $_POST["password"] ?? "";

    $input_hash = md5($password);

    // VULNERABLE: loose comparison — "0e..." == "0e..." evaluates as 0 == 0
    if ($input_hash == $stored_hash) {
        $message = "<p style='color:green'>Login successful! Flag: <b>$flag</b></p>";
    } else {
        $message = "<p style='color:red'>Invalid password. Your hash: $input_hash</p>";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>PHP Login</title></head>
<body>
<h1>Secure Login (PHP)</h1>
<form method="POST">
    <label>Password:</label><br>
    <input type="text" name="password" size="30"><br><br>
    <button type="submit">Login</button>
</form>
<?= $message ?>
<p><small>Hint: The stored hash starts with <code>0e</code>...</small></p>
</body>
</html>
