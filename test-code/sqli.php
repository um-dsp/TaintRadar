<?php
// mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
// $link = mysqli_connect("10.0.2.2", "root", "root", "ipark_skill_matchup");

// $unsan = $_POST['book_name'];
// $edition = (int)$_POST['edition'];
// $publisher = $_POST['publisher'];

// $book_name = mysqli_real_escape_string($_POST['book_name']);
$book_name = $_POST['edition'];
$san = intval($book_name);
// $publisher = mysqli_real_escape_string($_POST['publisher']);

$isbn = mysqli_query("SELECT isbn FROM BOOK_TABLE WHERE book_name='$book_name'") //AND edition = '$san'"); //vulnerable sink to SQLI
?>