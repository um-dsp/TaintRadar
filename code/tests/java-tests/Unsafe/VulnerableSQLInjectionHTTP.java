import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

public class VulnerableSQLInjectionHTTP {

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/login", new LoginHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("Server started on port 8000...");
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response;
            String username = null;
            String password = null;
            Scanner scanner = new Scanner(exchange.getRequestBody());
            while(scanner.hasNext()) {
                String[] parts = scanner.next().split("=");
                if (parts[0].equals("username")) {
                    username = parts[1];
                } else if (parts[0].equals("password")) {
                    password = parts[1];
                }
            }
            scanner.close();

            try {
                Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "root", "password");
                String sqlQuery = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery(sqlQuery);
                if (resultSet.next()) {
                    response = "User found: " + resultSet.getString("username");
                } else {
                    response = "User not found";
                }
                resultSet.close();
                statement.close();
                connection.close();
            } catch (SQLException e) {
                response = "Database error: " + e.getMessage();
            }

            exchange.sendResponseHeaders(200, response.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
