<?php
function getCustomerData($id, $name, $psswd) {
    $query = "SELECT * FROM USERS WHERE ID = ". $id . " AND USERNAME = " . $name . " AND PASSWORD = " . $psswd;
    return mysql_query($query);
}

$user_id = (int) $_COOKIE["uid"];
$username = $_POST["username"];
$name = mysql_escape_string($username);
$password = $_POST["password"];

$data = getCustomerData($user_id, $name, $password);
echo $data;
?>