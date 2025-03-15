<?php
function getName2() {
    $input = $_GET["name"];
    return $input;
}
function performSink2($x) {
    mysql_query($x);
}

$name = getName2();
$query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
performSink2($query);
?>