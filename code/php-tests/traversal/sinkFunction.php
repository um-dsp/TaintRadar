<?php
function main($x) {
    function performSink1($x) {
        mysql_query($x);
    }
    performSink1($x);
}

$name = $_GET["name"];
$query = "SELECT * FROM USERS WHERE USERNAME=" . $name;
main($query);
?>