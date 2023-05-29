<?php
$san = filter_input($_GET['username']);
$unsan = $_GET['password'];
mysql_query("SELECT * FROM USER_TABLE WHERE username='$san' AND password='$unsan");
?>