<?php
$input = $_GET['username'];
define("SAN", "HELLO");
define("UNSAN", "USERNAME: " . $input);
printf(SAN);
printf(UNSAN);
?>