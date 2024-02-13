<?php
$name = $_GET["name"];
$query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
mysql_query($query);
?>