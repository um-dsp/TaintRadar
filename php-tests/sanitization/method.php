<?php
function customSan($x) {
    $y = "INPUT: " . $x;
    $x = md5($y);
    return $x;
}

function customUnsan($x) {
    $x = $x . $_GET['input'];
    return $x;
}

?>