<?php

function customSan($x) {
    $tmp = $x;
    $y = filter_input($tmp);
    return $y;
}

$id = $_GET['id'];
$result = customSan($id);
eval($result);
?>