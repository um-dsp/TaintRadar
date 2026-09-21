<?php
$name = $_GET["name"];
trigger_error("Hello " . $name, E_USER_WARNING);
user_error("Hello " . $name);
vprintf("Hello %s", $name);
?>
