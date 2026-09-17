<?php
function customSanRef(&$p1) {
    $p1 = filter_input($p1);
}

function customUnsanRef(&$p1) {
    $p1 = $p1 . $_GET['input'];
}

$x = $_GET['input'];
$y = "Input: ";
customSanRef($x);
customUnsanRef($y);
echo $x . $y;
?>