<?php
$x = 0;
$y = $x + $_GET['input']; // coerces input to int
$z = $x . $_GET['input']; // concatenates input to string
$x = $x + $y;
echo $z;
?>