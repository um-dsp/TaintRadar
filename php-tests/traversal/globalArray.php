<?php
$params = $_GET;
$name = $params["name"];
$query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
mysql_query($query);
?>
