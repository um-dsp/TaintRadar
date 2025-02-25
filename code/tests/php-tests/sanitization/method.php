<?php
function customSan($x) {
    $y = "INPUT: " . $x;
    $x = filter_input($y);
    return $x;
}

function customUnsan($x) {
    $x = $x . $_GET['input'];
    return $x;
}

?>