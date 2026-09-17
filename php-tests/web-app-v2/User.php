<?php
/**
 * User class with various XSS vulnerabilities
 */
class User {
    private $username;
    private $email;
    private $profile_data;
    private $preferences;
    
    public function __construct($username, $email) {
        $this->username = $username;
        $this->email = $email;
        $this->profile_data = array();
        $this->preferences = array();
    }
    
    /**
     * XSS Bug Case #5: Object method with direct output
     * Complexity: Medium - XSS in class method
     */
    public function display_profile() {
        echo "<div class='user-profile'>";
        echo "<h3>Profile for: " . $this->username . "</h3>";
        echo "<p>Email: " . $this->email . "</p>";
        echo "</div>";
    }
    
    /**
     * XSS Bug Case #6: Object method with array iteration
     * Complexity: High - XSS in loop within object method
     */
    public function display_preferences() {
        echo "<div class='preferences'>";
        echo "<h4>User Preferences</h4>";
        echo "<ul>";
        foreach ($this->preferences as $key => $value) {
            echo "<li><strong>" . $key . ":</strong> " . $value . "</li>";
        }
        echo "</ul>";
        echo "</div>";
    }
    
    /**
     * XSS Bug Case #7: Method with callback/closure
     * Complexity: Very High - XSS through callback function
     */
    public function process_profile_data($callback) {
        foreach ($this->profile_data as $field => $data) {
            $processed = $callback($field, $data);
            echo "<div class='profile-field'>" . $processed . "</div>";
        }
    }
    
    /**
     * XSS Bug Case #8: Method chain with XSS
     * Complexity: High - XSS through method chaining
     */
    public function set_preference($key, $value) {
        $this->preferences[$key] = $value;
        return $this;
    }
    
    public function display_preference_summary() {
        $summary = "Preferences set: ";
        foreach ($this->preferences as $key => $value) {
            $summary .= $key . "=" . $value . "; ";
        }
        echo "<p class='pref-summary'>" . $summary . "</p>";
        return $this;
    }
    
    /**
     * XSS Bug Case #9: Static method with XSS
     * Complexity: Medium - XSS in static method
     */
    public static function display_user_list($users) {
        echo "<div class='user-list'>";
        echo "<h4>Active Users</h4>";
        foreach ($users as $user) {
            echo "<div class='user-item'>" . $user . "</div>";
        }
        echo "</div>";
    }
    
    /**
     * XSS Bug Case #10: Method with complex data processing
     * Complexity: Very High - XSS through complex data manipulation
     */
    public function generate_user_report($report_type) {
        $report_data = array();
        
        switch ($report_type) {
            case 'detailed':
                $report_data['title'] = "Detailed Report for " . $this->username;
                $report_data['content'] = $this->get_detailed_info();
                break;
            case 'summary':
                $report_data['title'] = "Summary for " . $this->username;
                $report_data['content'] = $this->get_summary_info();
                break;
            default:
                $report_data['title'] = "Report (" . $report_type . ") for " . $this->username;
                $report_data['content'] = "Custom report data";
        }
        
        echo "<div class='report'>";
        echo "<h3>" . $report_data['title'] . "</h3>";
        echo "<div class='report-content'>" . $report_data['content'] . "</div>";
        echo "</div>";
    }
    
    private function get_detailed_info() {
        return "Detailed information for " . $this->username . " (" . $this->email . ")";
    }
    
    private function get_summary_info() {
        return "Summary for " . $this->username;
    }
    
    // Setters for testing
    public function set_profile_data($data) {
        $this->profile_data = $data;
    }
    
    public function get_username() {
        return $this->username;
    }
}
?>
