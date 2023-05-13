<?php
if(!isset($_SESSION[’username’]))
    header( "Location: index.php" );
if (isset($_POST[’book_name’]))
    $book_name = mysql_real_escap_string($_POST[’book_name’]);
//sanitization
else
    $book_name ="";
if (isset($_POST[’edition’]))
    $edition = (int)$_POST[’edition’]; //user input is sanitized
else
    error();
// if (isset($_POST[’publisher’]) && strlen($_POST[’publisher’])<=35)
//     $publisher = str_replace(""", "\"", $_POST[’publisher’]);
// else
//     error();
$action = $_GET[’action’];
$isbn = query("SELECT isbn FROM BOOK_TABLE WHERE book_name=’$book_name’ AND edition = ’$edition’ AND publisher=’$publisher’"); //vulnerable sink to SQLI
if (mysql_num_rows( $isbn ) == 1){
    $_SESSION[’ISBN’] = $isbn;
    echo "<a href=’".BASE_URL."hold.php’> Hold the Book</a>";
}
?>

<!-- //client-side code starts
<html>
    <body>
        <form method="post" action="<?php echo $_SERVER[’PHP_SELF’]."?action=borrow"?>" onsubmit="validate()">
            <select name=’book_name’> //drop-down list
                <option value="Intro to CS by author1">Intro to CS</option>
                <option value="Intro to Math by author2">Intro to Math</option>
            </select>
            <input type=’text’ name=’publisher’>
            <input type=’text’ name=’edition’>
        </form>
        <script type="text/javascript">
            function validate() { //validates form upon submission
            var edition = document.getElementsByName("edition");
            if(edition.value <= 0) return false; // do not submit the form
            return true; //submit the form
            }
        </script>
    </body>
</html> -->