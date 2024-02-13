<?php
$id = $_POST['user_id'];
$comment = $_POST['comment'];
if (isset($id) and isset($comment)) {
    $link = mysqli_connect("localhost", "user", "psswd", "db");
    $sql = "INSERT INTO blog_posts VALUES (" . $id . "," . $comment . ")";
    mysqli_query($link, $sql);
}
?>