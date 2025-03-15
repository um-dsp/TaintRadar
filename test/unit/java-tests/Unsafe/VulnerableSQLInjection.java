import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class VulnerableSQLInjection {

    public static void main(String[] args) {
        String username = args[0]; // User input
        String password = args[1]; // User input

        try {
            // Establish database connection
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "root", "password");

            // Create SQL query with string concatenation (vulnerable to SQL injection)
            String sqlQuery = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";

            // Execute the SQL query
            Statement statement = connection.createStatement();
            statement.executeUpdate(sqlQuery);

            // Close resources
            statement.close();
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
