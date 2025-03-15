// Tainted version with taint-style vulnerabilities
function loginTainted(username, password) {
    var sqlQuery = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
    // Execute SQL query
    // Vulnerable to SQL injection
}

// Sanitized version with taint-style vulnerabilities
function loginSanitized(username, password) {
    // Sanitize inputs by escaping special characters
    username = escape(username);
    password = escape(password);

    var sqlQuery = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
    // Execute SQL query
    // Still vulnerable to SQL injection if escape function is insufficient
}

// Sanitized version with prepared statements (no taint-style vulnerabilities)
function loginPrepared(username, password) {
    // Use prepared statement to prevent SQL injection
    var sqlQuery = "SELECT * FROM users WHERE username=? AND password=?";
    // Execute SQL query
    // Not vulnerable to SQL injection as inputs are bound to placeholders
}

// Example usage
var username = document.getElementById('username').value; // Tainted input from user
var password = document.getElementById('password').value; // Tainted input from user
loginTainted(username, password);
loginSanitized(username, password);
loginPrepared(username, password);
