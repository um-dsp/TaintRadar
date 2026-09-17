<?php
class User {
  // Properties
  public $name = "DefaultName";
  public $id;

  // Methods
  function set_name($name) {
    $this->name = $name;
  }
  function get_name() {
    $x = $_GET['name'];
    return $x;
  }
}

$user1 = new User();
$user2 = new User();
$user1->set_name('Trevor');
$user2->set_name('Bernard');

$unsan =  $user1->get_name();
// echo $user2->get_name();
// $path = '';
// $filename = 'myfile';
// $file = array('name' => $path . $filename,
// 'is_dir' => is_dir($path . $filename),
// 'writable' => tep_is_writable($path . $filename),
// 'size' => filesize($path . $filename),
// 'last_modified' => strftime(DATE_TIME_FORMAT, filemtime($path . $filename)));
?>
