<?php
$link = mysqli_connect("localhost", "user", "psswd", "db");
$sql = "SELECT * FROM blog_posts";
$result = mysqli_query($link, $sql);
$rows = mysqli_fetch_all($result, MYSQLI_ASSOC);
foreach ($rows as $row) {
    printf("User: %s - Comment: %s\n", $row["id"], $row["Comment"]);
}
?>