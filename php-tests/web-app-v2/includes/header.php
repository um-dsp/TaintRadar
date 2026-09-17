<?php
/**
 * Header file included by other pages
 * Contains XSS vulnerabilities through included content
 */

// Get page title from URL parameter or use default
$page_title = isset($_GET['title']) ? $_GET['title'] : 'Default Page';

/**
 * XSS Bug Case #11: Included file with XSS in global scope
 * Complexity: Medium - XSS in included file affects multiple pages
 */
function render_page_header($title, $subtitle = '') {
    echo "<!DOCTYPE html>";
    echo "<html>";
    echo "<head>";
    echo "<title>" . $title . "</title>";
    echo "<style>";
    echo "body { font-family: Arial, sans-serif; margin: 20px; }";
    echo ".header { background: #f0f0f0; padding: 20px; border-radius: 5px; }";
    echo ".alert { padding: 10px; margin: 10px 0; background: #ffeb3b; }";
    echo ".user-profile { border: 1px solid #ccc; padding: 15px; margin: 10px 0; }";
    echo ".menu { list-style: none; padding: 0; }";
    echo ".menu li { display: inline-block; margin-right: 15px; }";
    echo "</style>";
    echo "</head>";
    echo "<body>";
    echo "<div class='header'>";
    echo "<h1>" . $title . "</h1>";
    if ($subtitle) {
        echo "<h2>" . $subtitle . "</h2>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #12: Navigation function with dynamic content
 * Complexity: High - XSS through dynamic navigation generation
 */
function render_navigation($current_page = '') {
    $nav_items = array(
        'home' => 'Home',
        'profile' => 'Profile',
        'search' => 'Search',
        'admin' => 'Admin Panel'
    );
    
    echo "<nav class='main-nav'>";
    echo "<ul class='menu'>";
    foreach ($nav_items as $page => $label) {
        $class = ($page === $current_page) ? "active" : "";
        $link_text = $label;
        if (isset($_GET['nav_suffix'])) {
            $link_text .= " " . $_GET['nav_suffix'];
        }
        echo "<li class='" . $class . "'><a href='" . $page . ".php'>" . $link_text . "</a></li>";
    }
    echo "</ul>";
    echo "</nav>";
}

/**
 * XSS Bug Case #13: Footer with user-generated content
 * Complexity: Medium - XSS in footer section
 */
function render_footer($custom_message = '') {
    echo "<footer>";
    echo "<hr>";
    if ($custom_message) {
        echo "<p>Custom message: " . $custom_message . "</p>";
    }
    echo "<p>&copy; 2024 Vulnerable Web App. Current user: " . 
         (isset($_SESSION['username']) ? $_SESSION['username'] : 'Guest') . "</p>";
    echo "</footer>";
    echo "</body>";
    echo "</html>";
}

// Global variables that can be used by including pages
$header_message = isset($_GET['header_msg']) ? $_GET['header_msg'] : '';
$debug_info = isset($_GET['debug']) ? $_GET['debug'] : '';
?>
