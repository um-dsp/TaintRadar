<?php
$literal = 0;
$unsan = $HTTP_GET_VARS['input'];
// settype($unsan,"integer");
$intCast = (integer)$unsan;
$san = filter_input($unsan);
$san = $san + 1;
$unsan = $unsan + " !";
$addSan = $literal + $san + $intCast;
$addUnsan = $literal + $san + $unsan;
print($addSan);
print($addUnsan);
?>