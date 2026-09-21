<?php
$san15 = 0;
$unsan15 = $_GET['input'];
$san16 = md5($unsan15);
$san15 = $san15 . $san16;
$tmp0 = $san15;
$tmp0 = $tmp0 . $unsan15;
?>