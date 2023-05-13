<?php
$literal = 0;
$unsan = $_GET['input'];
$intCast = int($unsan);
$san = filter_input($unsan);
$san = $san + 1;
$unsan = $unsan + " !";
$addSan = $literal + $san + $intCast;
$addUnsan = $literal + $san + $unsan;
eval($addSan);
eval($addUnsan);
?>