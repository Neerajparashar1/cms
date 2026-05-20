<?php
// database.php ko call karein
require_once 'database.php';

try {
    // Agar aapka baki code MySQLi use karta hai:
    $conn = getMysqliConnection();
    echo "MySQLi Connection Successful! <br>";

    // Agar aapka baki code PDO use karta hai:
    $database = new Database();
    $db = $database->getConnection();
    echo "PDO Connection Successful!";
} catch (Exception $e) {
    echo "Kuch gadbad hai: " . $e->getMessage();
}
?>