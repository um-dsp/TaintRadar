<?php
$name = $_GET["name"];
$unsanquery = "SELECT * FROM USERS WHERE USERNAME=" . $name;
mysql_query($unsanquery);
$sanquery = mysql_escape_string($unsanquery);
mysql_query($sanquery)
?>
