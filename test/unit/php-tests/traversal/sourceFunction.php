<?php
function getName1() {
    $input = $_GET["name"];
    return $input;
}

function getNameFrom1($x) {
    $input = $_GET[$x];
    return $input;
}
$name = getNameFrom1("name");
$query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
mysql_query($query);
?>