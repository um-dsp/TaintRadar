-- Schema for the second-order XSS example: insert.php writes an attacker-controlled
-- comment into blog_posts and display.php prints the rows it reads back.
CREATE TABLE `blog_posts` (
  `id` int(10) NOT NULL,
  `Comment` varchar(255) NOT NULL
);
