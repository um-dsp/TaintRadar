<?php
// Configuration file with shared functions and variables

// Database configuration
$db_host = "localhost";
$db_name = "testapp";
$db_user = "root";
$db_pass = "";

// Global variables used throughout the application
$app_name = "Vulnerable Web App v2.0";
$debug_mode = true;

/**
 * XSS Bug Case #1: Simple utility function with direct output
 * Complexity: Low - Direct parameter output without sanitization
 */
function display_message($message) {
    echo "<div class='alert'>" . $message . "</div>";
}

/**
 * XSS Bug Case #2: Function with conditional logic
 * Complexity: Medium - XSS vulnerability depends on condition
 */
function show_user_greeting($username, $is_admin = false) {
    if ($is_admin) {
        echo "<h2>Admin Dashboard - Welcome " . $username . "</h2>";
    } else {
        echo "<h3>User Panel - Hello " . $username . "</h3>";
    }
}

/**
 * XSS Bug Case #3: Function with string manipulation
 * Complexity: Medium - XSS through string concatenation and manipulation
 */
function format_search_results($query, $results_count) {
    $formatted_query = strtoupper($query);
    $message = "Search results for '" . $formatted_query . "' - Found " . $results_count . " items";
    return "<p class='search-info'>" . $message . "</p>";
}

/**
 * XSS Bug Case #4: Recursive function with XSS
 * Complexity: High - XSS in recursive function call
 */
function build_navigation_menu($menu_items, $level = 0) {
    $html = "<ul class='menu level-" . $level . "'>";
    foreach ($menu_items as $item) {
        if (is_array($item)) {
            $html .= "<li>" . $item['title'] . build_navigation_menu($item['children'], $level + 1) . "</li>";
        } else {
            $html .= "<li>" . $item . "</li>";
        }
    }
    $html .= "</ul>";
    return $html;
}

/**
 * Safe function for comparison - properly sanitized
 */
function safe_display_message($message) {
    echo "<div class='alert'>" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</div>";
}

// Session configuration
session_start();
?>
