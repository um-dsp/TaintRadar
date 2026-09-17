<?php
function getDataFromName() {
    $name = $_GET["name"];
    $query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
    return mysql_query($query);
}

$data = getDataFromName();

?>