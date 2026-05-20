<?php
$password = "Admin@123";
$hash = password_hash($password, PASSWORD_BCRYPT);
echo "Hash: " . $hash;
?>