<?php
function customSan($x) {
    $y = "INPUT: " . $x;
    $x = filter_input($y);
    return $x;
}
?>