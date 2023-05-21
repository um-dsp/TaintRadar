<?php
// Literals
$san0 = 0;
$san1 = 2.3;
$san2 = "Hello World";

// Assignment propagation
$unsan0 = $_GET['input'];
$san3 = filter_input($unsan0);
$san4 = $san3 + " .";
$san4 = $san4 + $san3;
$unsan1 = $unsan0 + $san4;

// Type casting
$san5 = (integer)$unsan0;
$san6 = (string)$san3;
$unsan2 = (string)$unsan0;
$typeSan = $unsan1;
$unsan2 = $unsan1;
settype($typeSan, "double");
settype($unsan2, "string");
$san7 = $typeSan + 1.1;

// Functions (by ralue)
function customSan($p1) {
    $unsan3 = $p1;
    $san8 = filter_input($unsan3);
    return $san8;
}
$san9 = customSan($unsan1);

function customUnsan($p1) {
    $unsan5 = $_GET["input"] . $p2;
    return $unsan5;
}
$unsan6 = customUnsan($san6);

function getInput() {
    return $_GET['input'];
}
$unsan7 = getInput();

function addTwo($p1, $p2) {
    $tmp = $p1 . $p2;
    return $tmp;
}
$san10 = addTwo($san1, $san2);
$unsan8 = addTwo($san1, $unsan2);

function customSan2nd($p1, $p2) {
    return $p1 . filter_input($p2);
}
$san11 = customSan2nd($san3, $unsan2);
$unsan9 = customSan2nd($unsan1, $unsan2);
$unsan10 = customSan2nd($unsan1, $san2);

// Functions (by reference)
function customSanRef(&$p1) {
    $p1 = filter_input($p1);
}
$san12 = $unsan10;
customSanRef($san12);

function customAddRef(&$p1, $p2) {
    $p1 = $p1 . $p2;
}
$san13 = 0;
customAddRef($san13, $san0);
?>