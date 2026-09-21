<?php
$name = $_GET["name"];
if (is_numeric($name)) {
  $query = "SELECT * FROM USERS WHERE ID=" . $name;
  mysql_query($query);
}
?>
