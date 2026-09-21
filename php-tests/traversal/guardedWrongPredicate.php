<?php
$name = $_GET["name"];
if (is_string($name)) {
  $query = "SELECT * FROM USERS WHERE USERNAME='" . $name . "'";
  mysql_query($query);
}
?>
