<?php
/**
 * Login page with advanced XSS vulnerabilities
 * Demonstrates complex patterns including:
 * - Session-based XSS
 * - Cookie-based XSS  
 * - Include-based vulnerabilities
 * - Database simulation with XSS
 */

// Include dependencies without explicit require in main scope
include_once 'config.php';
include_once 'User.php';
include_once 'includes/header.php';

// Simulate database connection
$db_connected = true;

/**
 * XSS Bug Case #23: Session-based XSS vulnerability
 * Complexity: High - XSS persists across requests through session
 */
if (isset($_POST['remember_user']) && $_POST['remember_user']) {
    $_SESSION['remembered_username'] = $_POST['username'];
    $_SESSION['last_login_message'] = "Welcome back, " . $_POST['username'];
}

/**
 * XSS Bug Case #24: Cookie-based XSS vulnerability
 * Complexity: High - XSS through cookie manipulation
 */
if (isset($_POST['save_preferences'])) {
    setcookie('user_theme', $_POST['theme'], time() + 3600);
    setcookie('user_language', $_POST['language'], time() + 3600);
    setcookie('display_name', $_POST['display_name'], time() + 3600);
}

/**
 * XSS Bug Case #25: Include file vulnerability with dynamic inclusion
 * Complexity: Very High - XSS through dynamic file inclusion
 */
function load_user_template($template_name, $user_data) {
    $template_path = 'templates/' . $template_name . '.php';
    
    // Simulate template content (in real scenario this would be a file)
    $template_content = "
    <div class='user-template'>
        <h3>Template: " . $template_name . "</h3>
        <p>User: " . $user_data['name'] . "</p>
        <p>Status: " . $user_data['status'] . "</p>
    </div>";
    
    eval("?>" . $template_content);
}

/**
 * XSS Bug Case #26: Database simulation with XSS
 * Complexity: Very High - XSS through simulated database operations
 */
function simulate_database_query($query, $params = array()) {
    // Simulate database results with user input
    $results = array();
    
    if (strpos($query, 'SELECT') !== false) {
        foreach ($params as $key => $value) {
            $results[] = array(
                'id' => rand(1, 100),
                'field_name' => $key,
                'field_value' => $value,
                'query_type' => 'SELECT'
            );
        }
    }
    
    return $results;
}

function display_query_results($results) {
    echo "<div class='db-results'>";
    echo "<h4>Database Query Results</h4>";
    foreach ($results as $row) {
        echo "<div class='db-row'>";
        echo "<p>ID: " . $row['id'] . "</p>";
        echo "<p>Field: " . $row['field_name'] . "</p>";
        echo "<p>Value: " . $row['field_value'] . "</p>";
        echo "<p>Type: " . $row['query_type'] . "</p>";
        echo "</div>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #27: Advanced form processing with file upload simulation
 * Complexity: Very High - XSS through file upload metadata
 */
function process_file_upload($file_info) {
    echo "<div class='file-upload-result'>";
    echo "<h4>File Upload Processing</h4>";
    echo "<p>Original Name: " . $file_info['original_name'] . "</p>";
    echo "<p>File Type: " . $file_info['type'] . "</p>";
    echo "<p>Description: " . $file_info['description'] . "</p>";
    echo "<p>Upload Status: " . $file_info['status'] . "</p>";
    echo "</div>";
}

// Start page rendering
render_page_header("Login - " . $app_name, "User Authentication");
render_navigation('login');

/**
 * XSS Bug Case #28: Login error messages
 * Complexity: Medium - XSS through error message display
 */
if (isset($_GET['error'])) {
    echo "<div class='error-message'>";
    echo "<h3>Login Error</h3>";
    echo "<p>Error: " . $_GET['error'] . "</p>";
    echo "</div>";
}

/**
 * XSS Bug Case #29: Redirect URL vulnerability
 * Complexity: High - XSS through redirect parameter
 */
if (isset($_GET['redirect_to'])) {
    echo "<div class='redirect-info'>";
    echo "<p>After login, you will be redirected to: " . $_GET['redirect_to'] . "</p>";
    echo "</div>";
}

/**
 * XSS Bug Case #30: Session restoration
 * Complexity: High - XSS from session data
 */
if (isset($_SESSION['remembered_username'])) {
    echo "<div class='remembered-user'>";
    echo "<p>Remembered user: " . $_SESSION['remembered_username'] . "</p>";
    if (isset($_SESSION['last_login_message'])) {
        echo "<p>" . $_SESSION['last_login_message'] . "</p>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #31: Cookie-based display
 * Complexity: High - XSS from cookie values
 */
if (isset($_COOKIE['display_name'])) {
    echo "<div class='user-preferences'>";
    echo "<h4>Your Preferences</h4>";
    echo "<p>Display Name: " . $_COOKIE['display_name'] . "</p>";
    if (isset($_COOKIE['user_theme'])) {
        echo "<p>Theme: " . $_COOKIE['user_theme'] . "</p>";
    }
    if (isset($_COOKIE['user_language'])) {
        echo "<p>Language: " . $_COOKIE['user_language'] . "</p>";
    }
    echo "</div>";
}

/**
 * XSS Bug Case #32: Login attempt processing
 * Complexity: Very High - XSS through complex login logic
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Simulate login validation
    $login_attempts = isset($_POST['previous_attempts']) ? 
                     json_decode($_POST['previous_attempts'], true) : array();
    
    $current_attempt = array(
        'username' => $username,
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    );
    
    array_push($login_attempts, $current_attempt);
    
    echo "<div class='login-attempts'>";
    echo "<h4>Login Attempt History</h4>";
    foreach ($login_attempts as $index => $attempt) {
        echo "<div class='attempt-" . $index . "'>";
        echo "<p>Attempt #" . ($index + 1) . "</p>";
        echo "<p>User: " . $attempt['username'] . "</p>";
        echo "<p>Time: " . $attempt['timestamp'] . "</p>";
        echo "<p>IP: " . $attempt['ip'] . "</p>";
        echo "<p>Agent: " . $attempt['user_agent'] . "</p>";
        echo "</div>";
    }
    echo "</div>";
    
    // Simulate database query for user verification
    if ($db_connected) {
        $query_params = array(
            'username' => $username,
            'search_term' => isset($_POST['search_hint']) ? $_POST['search_hint'] : '',
            'login_source' => isset($_POST['login_source']) ? $_POST['login_source'] : 'web'
        );
        
        $results = simulate_database_query("SELECT * FROM users WHERE username = ?", $query_params);
        display_query_results($results);
    }
}

/**
 * XSS Bug Case #33: Template loading with user data
 * Complexity: Very High - XSS through dynamic template system
 */
if (isset($_POST['load_template'])) {
    $template_name = $_POST['template_type'];
    $user_data = array(
        'name' => $_POST['template_user'],
        'status' => $_POST['user_status']
    );
    
    load_user_template($template_name, $user_data);
}

/**
 * XSS Bug Case #34: File upload processing
 * Complexity: Very High - XSS through file metadata
 */
if (isset($_POST['process_upload'])) {
    $file_info = array(
        'original_name' => $_POST['file_name'],
        'type' => $_POST['file_type'],
        'description' => $_POST['file_description'],
        'status' => 'Uploaded successfully'
    );
    
    process_file_upload($file_info);
}

/**
 * XSS Bug Case #35: Advanced user profile creation
 * Complexity: Very High - XSS through complex object manipulation
 */
if (isset($_POST['create_profile'])) {
    $profile_username = $_POST['profile_username'];
    $profile_email = $_POST['profile_email'];
    
    $new_user = new User($profile_username, $profile_email);
    
    // Set complex profile data
    $profile_data = array();
    if (isset($_POST['bio'])) {
        $profile_data['bio'] = $_POST['bio'];
    }
    if (isset($_POST['website'])) {
        $profile_data['website'] = $_POST['website'];
    }
    if (isset($_POST['social_links'])) {
        $social_links = explode(',', $_POST['social_links']);
        foreach ($social_links as $index => $link) {
            $profile_data['social_' . $index] = trim($link);
        }
    }
    
    $new_user->set_profile_data($profile_data);
    
    echo "<div class='profile-creation'>";
    echo "<h3>Profile Created Successfully</h3>";
    $new_user->display_profile();
    
    // Display profile data with callback
    $new_user->process_profile_data(function($field, $data) use ($profile_username) {
        return "Profile field for " . $profile_username . " - " . $field . ": " . $data;
    });
    
    echo "</div>";
}
?>

<!-- Login Forms -->
<div class="login-section">
    <h3>Login Forms</h3>
    
    <!-- Basic Login Form -->
    <form method="post" action="">
        <h4>Basic Login (Bug Cases #28, #32)</h4>
        <input type="text" name="username" placeholder="Username" required />
        <input type="password" name="password" placeholder="Password" required />
        <input type="text" name="search_hint" placeholder="Search hint (optional)" />
        <input type="text" name="login_source" placeholder="Login source" />
        <input type="hidden" name="previous_attempts" value='[]' />
        <label>
            <input type="checkbox" name="remember_user" value="1" /> Remember me
        </label>
        <button type="submit" name="login">Login</button>
    </form>
    
    <!-- Preferences Form -->
    <form method="post" action="">
        <h4>Save Preferences (Bug Case #24, #31)</h4>
        <input type="text" name="display_name" placeholder="Display Name" />
        <input type="text" name="theme" placeholder="Theme" />
        <input type="text" name="language" placeholder="Language" />
        <button type="submit" name="save_preferences">Save Preferences</button>
    </form>
    
    <!-- Template Loading Form -->
    <form method="post" action="">
        <h4>Load User Template (Bug Case #33)</h4>
        <input type="text" name="template_type" placeholder="Template type" />
        <input type="text" name="template_user" placeholder="Username for template" />
        <input type="text" name="user_status" placeholder="User status" />
        <button type="submit" name="load_template">Load Template</button>
    </form>
    
    <!-- File Upload Simulation -->
    <form method="post" action="">
        <h4>File Upload Simulation (Bug Case #34)</h4>
        <input type="text" name="file_name" placeholder="File name" />
        <input type="text" name="file_type" placeholder="File type" />
        <input type="text" name="file_description" placeholder="File description" />
        <button type="submit" name="process_upload">Process Upload</button>
    </form>
    
    <!-- Profile Creation Form -->
    <form method="post" action="">
        <h4>Create User Profile (Bug Case #35)</h4>
        <input type="text" name="profile_username" placeholder="Username" />
        <input type="email" name="profile_email" placeholder="Email" />
        <textarea name="bio" placeholder="Bio"></textarea>
        <input type="text" name="website" placeholder="Website URL" />
        <input type="text" name="social_links" placeholder="Social links (comma separated)" />
        <button type="submit" name="create_profile">Create Profile</button>
    </form>
</div>

<div class="url-examples">
    <h3>URL Examples for Testing Login XSS</h3>
    <ul>
        <li><a href="?error=<script>alert('XSS Case 28')</script>">Bug Case #28: Error message XSS</a></li>
        <li><a href="?redirect_to=<script>alert('XSS Case 29')</script>">Bug Case #29: Redirect URL XSS</a></li>
        <li><a href="javascript:document.cookie='display_name=<script>alert(1)</script>'; location.reload();">Bug Case #31: Cookie XSS</a></li>
    </ul>
</div>

<?php
render_footer("Login page - " . (isset($_GET['page_info']) ? $_GET['page_info'] : 'Secure area'));
?>