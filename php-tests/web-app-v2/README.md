# Vulnerable Web Application v2.0 - XSS Test Suite

This PHP web application contains **35 distinct XSS vulnerabilities** across multiple complexity levels, designed for security testing and vulnerability analysis.

## File Structure

```
web-app-v2/
├── index.php           # Main page with 22 XSS bugs
├── login.php           # Login page with 13 XSS bugs  
├── config.php          # Configuration with shared vulnerable functions
├── User.php            # User class with object-oriented XSS bugs
└── includes/
    └── header.php      # Header file with inclusion-based XSS bugs
```

## XSS Vulnerability Catalog

### **Low Complexity (Direct Output)**
- **Case #1** (`config.php`): `display_message()` function - Direct parameter output
- **Case #14** (`index.php`): Direct GET parameter output via `$_GET['welcome_msg']`

### **Medium Complexity (Conditional/Functional)**
- **Case #2** (`config.php`): `show_user_greeting()` - Conditional XSS based on admin status
- **Case #3** (`config.php`): `format_search_results()` - XSS through string manipulation
- **Case #5** (`User.php`): `display_profile()` - Object method XSS
- **Case #9** (`User.php`): `display_user_list()` - Static method XSS
- **Case #11** (`includes/header.php`): `render_page_header()` - Included file XSS
- **Case #13** (`includes/header.php`): `render_footer()` - Footer XSS
- **Case #16** (`index.php`): Function call XSS using imported `display_message()`
- **Case #28** (`login.php`): Login error messages via `$_GET['error']`

### **High Complexity (Loops/Objects/Conditions)**
- **Case #4** (`config.php`): `build_navigation_menu()` - Recursive function XSS
- **Case #6** (`User.php`): `display_preferences()` - Array iteration XSS
- **Case #8** (`User.php`): Method chaining XSS
- **Case #12** (`includes/header.php`): `render_navigation()` - Dynamic navigation XSS
- **Case #15** (`index.php`): POST data loop processing
- **Case #17** (`index.php`): Conditional XSS based on multiple GET parameters
- **Case #21** (`index.php`): Static method call with user input
- **Case #23** (`login.php`): Session-based persistent XSS
- **Case #24** (`login.php`): Cookie-based XSS vulnerability
- **Case #29** (`login.php`): Redirect URL vulnerability
- **Case #30** (`login.php`): Session restoration XSS
- **Case #31** (`login.php`): Cookie-based display XSS

### **Very High Complexity (Advanced Patterns)**
- **Case #7** (`User.php`): `process_profile_data()` - Callback/closure XSS
- **Case #10** (`User.php`): `generate_user_report()` - Complex data processing XSS
- **Case #18** (`index.php`): Search functionality with multiple transformations
- **Case #19** (`index.php`): Dynamic menu with recursive JSON processing
- **Case #20** (`index.php`): Object instantiation and method calls
- **Case #22** (`index.php`): Complex form processing with nested loops
- **Case #25** (`login.php`): Dynamic file inclusion vulnerability
- **Case #26** (`login.php`): Database simulation XSS
- **Case #27** (`login.php`): File upload metadata XSS
- **Case #32** (`login.php`): Complex login attempt processing
- **Case #33** (`login.php`): Template loading with user data
- **Case #34** (`login.php`): File upload processing XSS
- **Case #35** (`login.php`): Advanced user profile creation

## Complex Pattern Categories

### **File Inclusion Vulnerabilities**
- Import-based XSS through `config.php` functions
- Header file inclusion affecting multiple pages
- Dynamic template loading simulation

### **Object-Oriented XSS**
- Class method vulnerabilities
- Static method XSS
- Method chaining vulnerabilities
- Callback function XSS

### **Loop-Based XSS**
- Array iteration vulnerabilities
- Nested loop processing
- Recursive function XSS

### **Session & Cookie XSS**
- Persistent XSS through sessions
- Cookie manipulation vulnerabilities
- Cross-request XSS persistence

### **Database Simulation XSS**
- Query parameter injection
- Result set display vulnerabilities
- Simulated ORM-style XSS

## Test URLs for Manual Testing

### Index Page Tests
```
# Basic XSS
/?welcome_msg=<script>alert('XSS Case 14')</script>

# Function-based XSS
/?msg=<script>alert('XSS Case 16')</script>

# Conditional XSS
/?user=<script>alert('XSS Case 17')</script>&admin=true

# Search XSS
/?search=<script>alert('XSS Case 18')</script>

# Object XSS
/?user_demo=1&username=<script>alert('XSS Case 20')</script>

# Recursive menu XSS
/?menu_data={"title":"<script>alert('XSS Case 19')</script>","children":[]}

# Static method XSS  
/?show_users=<script>alert('XSS Case 21')</script>,user2
```

### Login Page Tests
```
# Error message XSS
/login.php?error=<script>alert('XSS Case 28')</script>

# Redirect XSS
/login.php?redirect_to=<script>alert('XSS Case 29')</script>

# Cookie XSS (run in browser console)
document.cookie='display_name=<script>alert(1)</script>'; location.reload();
```

## Form-Based Testing

The application includes multiple forms for testing POST-based XSS:

1. **Comments Form**: Tests array processing XSS
2. **Search Form**: Tests search functionality XSS  
3. **Complex Form**: Tests nested form data XSS
4. **Login Forms**: Tests authentication-related XSS
5. **Profile Creation**: Tests object-oriented XSS

## Security Analysis Notes

This application demonstrates how XSS vulnerabilities can manifest in:

- **Direct output** without sanitization
- **Function parameters** passed between files
- **Object methods** and static calls
- **Loop constructs** processing user arrays
- **Session/cookie** persistent storage
- **Recursive functions** and callbacks
- **Complex data structures** and JSON processing
- **Simulated database** operations
- **File inclusion** and template systems

## Remediation Examples

For comparison, the `config.php` file includes one properly sanitized function:

```php
function safe_display_message($message) {
    echo "<div class='alert'>" . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . "</div>";
}
```

All other functions demonstrate various XSS vulnerability patterns for educational and testing purposes.

## Usage for Security Testing

1. Deploy the application on a local PHP server
2. Use the provided test URLs to trigger XSS vulnerabilities
3. Submit forms with XSS payloads to test POST-based vulnerabilities
4. Analyze the code patterns to understand vulnerability root causes
5. Test automated security scanners against the application
6. Practice manual penetration testing techniques

**⚠️ WARNING**: This application contains intentional security vulnerabilities. Only use in isolated testing environments. Never deploy to production systems.
