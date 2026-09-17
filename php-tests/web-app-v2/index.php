<?php
/**
 * Main index page with various XSS vulnerabilities
 * This file demonstrates complex XSS patterns including:
 * - File inclusion vulnerabilities
 * - Function-based XSS
 * - Loop-based XSS
 * - Object-oriented XSS
 */

// Include configuration and dependencies
require_once 'config.php';
require_once 'User.php';
require_once 'includes/header.php';

// Start page rendering
render_page_header($app_name, $header_message);
render_navigation('home');

// Display debug information if requested
if ($debug_mode && $debug_info) {
    echo "<div class='debug-info'>";
    echo "<h4>Debug Information</h4>";
    echo "<p>Debug: " . $debug_info . "</p>";
    echo "</div>";
}

/**
 * XSS Bug Case #14: Direct GET parameter output
 * Complexity: Low - Simple direct output of user input
 */
if (isset($_GET['welcome_msg'])) {
    echo "<div class='welcome'>";
    echo "<h3>Welcome Message</h3>";
    echo "<p>" . $_GET['welcome_msg'] . "</p>";
    echo "</div>";
}

/**
 * XSS Bug Case #15: POST data with loop processing
 * Complexity: High - XSS through form data processing in loops
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comments'])) {
    echo "<div class='comments-section'>";
    echo "<h3>User Comments</h3>";
    
    $comments = $_POST['comments'];
    for ($i = 0; $i < count($comments); $i++) {
        echo "<div class='comment-" . $i . "'>";
        echo "<p>Comment #" . ($i + 1) . ": " . $comments[$i] . "</p>";
        echo "</div>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #16: Function call with user input
 * Complexity: Medium - XSS through function imported from config.php
 */
if (isset($_GET['msg'])) {
    display_message($_GET['msg']);
}

/**
 * XSS Bug Case #17: Conditional function calls
 * Complexity: High - XSS depends on multiple conditions
 */
if (isset($_GET['user']) && isset($_GET['admin'])) {
    $is_admin = ($_GET['admin'] === 'true');
    show_user_greeting($_GET['user'], $is_admin);
}

/**
 * XSS Bug Case #18: Search functionality with complex processing
 * Complexity: Very High - XSS through search with multiple transformations
 */
if (isset($_GET['search']) || isset($_POST['search_query'])) {
    $search_query = isset($_GET['search']) ? $_GET['search'] : $_POST['search_query'];
    $results_count = rand(1, 100); // Simulate search results
    
    echo format_search_results($search_query, $results_count);
    
    // Additional search processing
    $processed_terms = explode(' ', $search_query);
    echo "<div class='search-terms'>";
    echo "<h4>Search Terms Analysis</h4>";
    foreach ($processed_terms as $index => $term) {
        $highlighted_term = "<span class='term-" . $index . "'>" . $term . "</span>";
        echo "<p>Term " . ($index + 1) . ": " . $highlighted_term . "</p>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #19: Dynamic menu generation with recursive function
 * Complexity: Very High - XSS in recursive function from config.php
 */
if (isset($_GET['menu_data'])) {
    $menu_structure = json_decode($_GET['menu_data'], true);
    if ($menu_structure) {
        echo "<div class='dynamic-menu'>";
        echo "<h3>Dynamic Navigation</h3>";
        echo build_navigation_menu($menu_structure);
        echo "</div>";
    }
}

/**
 * XSS Bug Case #20: Object instantiation and method calls
 * Complexity: Very High - XSS through object methods
 */
if (isset($_GET['user_demo'])) {
    $username = isset($_GET['username']) ? $_GET['username'] : 'DefaultUser';
    $email = isset($_GET['email']) ? $_GET['email'] : 'user@example.com';
    
    $user = new User($username, $email);
    
    // Set some profile data for demonstration
    if (isset($_GET['profile_data'])) {
        $profile_data = json_decode($_GET['profile_data'], true);
        if ($profile_data) {
            $user->set_profile_data($profile_data);
        }
    }
    
    echo "<div class='user-demo'>";
    echo "<h3>User Profile Demo</h3>";
    
    // Display basic profile
    $user->display_profile();
    
    // Set and display preferences with method chaining
    if (isset($_GET['theme']) || isset($_GET['language'])) {
        $theme = isset($_GET['theme']) ? $_GET['theme'] : 'default';
        $language = isset($_GET['language']) ? $_GET['language'] : 'en';
        
        $user->set_preference('theme', $theme)
             ->set_preference('language', $language)
             ->display_preference_summary();
    }
    
    // Process profile data with callback
    if (isset($_GET['use_callback']) && $_GET['use_callback'] === 'true') {
        $user->process_profile_data(function($field, $data) {
            return "<strong>" . $field . ":</strong> " . $data;
        });
    }
    
    // Generate user report
    if (isset($_GET['report_type'])) {
        $user->generate_user_report($_GET['report_type']);
    }
    
    echo "</div>";
}

/**
 * XSS Bug Case #21: Static method call with user input
 * Complexity: High - XSS through static method
 */
if (isset($_GET['show_users'])) {
    $user_list = explode(',', $_GET['show_users']);
    User::display_user_list($user_list);
}

/**
 * XSS Bug Case #22: Complex form processing with nested loops
 * Complexity: Very High - XSS through complex form data structures
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['form_data'])) {
    echo "<div class='form-results'>";
    echo "<h3>Form Processing Results</h3>";
    
    foreach ($_POST['form_data'] as $section => $data) {
        echo "<div class='section-" . $section . "'>";
        echo "<h4>Section: " . $section . "</h4>";
        
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (is_array($value)) {
                    echo "<div class='subsection'>";
                    echo "<h5>" . $key . "</h5>";
                    foreach ($value as $subkey => $subvalue) {
                        echo "<p>" . $subkey . ": " . $subvalue . "</p>";
                    }
                    echo "</div>";
                } else {
                    echo "<p>" . $key . ": " . $value . "</p>";
                }
            }
        } else {
            echo "<p>Data: " . $data . "</p>";
        }
        echo "</div>";
    }
    echo "</div>";
}

// Sample forms for testing
?>

<div class="forms-section">
    <h3>Test Forms</h3>
    
    <!-- Simple comment form -->
    <form method="post" action="">
        <h4>Comments Form (Bug Case #15)</h4>
        <input type="text" name="comments[]" placeholder="Comment 1" />
        <input type="text" name="comments[]" placeholder="Comment 2" />
        <input type="text" name="comments[]" placeholder="Comment 3" />
        <button type="submit">Submit Comments</button>
    </form>
    
    <!-- Search form -->
    <form method="post" action="">
        <h4>Search Form (Bug Case #18)</h4>
        <input type="text" name="search_query" placeholder="Enter search terms" />
        <button type="submit">Search</button>
    </form>
    
    <!-- Complex form data -->
    <form method="post" action="">
        <h4>Complex Form (Bug Case #22)</h4>
        <input type="text" name="form_data[personal][name]" placeholder="Name" />
        <input type="text" name="form_data[personal][email]" placeholder="Email" />
        <input type="text" name="form_data[preferences][theme]" placeholder="Theme" />
        <input type="text" name="form_data[preferences][settings][notifications]" placeholder="Notifications" />
        <button type="submit">Submit Complex Form</button>
    </form>
</div>

<div class="url-examples">
    <h3>URL Examples for Testing XSS</h3>
    <ul>
        <li><a href="?welcome_msg=<script>alert('XSS Case 14')</script>">Bug Case #14: Direct GET output</a></li>
        <li><a href="?msg=<script>alert('XSS Case 16')</script>">Bug Case #16: Function call XSS</a></li>
        <li><a href="?user=<script>alert('XSS Case 17')</script>&admin=true">Bug Case #17: Conditional XSS</a></li>
        <li><a href="?search=<script>alert('XSS Case 18')</script>">Bug Case #18: Search XSS</a></li>
        <li><a href="?user_demo=1&username=<script>alert('XSS Case 20')</script>">Bug Case #20: Object XSS</a></li>
        <li><a href="?show_users=<script>alert('XSS Case 21')</script>,user2">Bug Case #21: Static method XSS</a></li>
    </ul>
</div>

<?php
render_footer(isset($_GET['footer_msg']) ? $_GET['footer_msg'] : '');
?>