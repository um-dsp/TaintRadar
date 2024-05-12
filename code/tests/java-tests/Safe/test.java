import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;

public class test {
    String x = "Hello World";
    public final String message = "Hey there!";
    Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "root", "password");

    public String unsan(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        return comment;
    }

    public String san(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        comment = connection.escape(comment);
        return comment;
    }

    public static void main(String[] args) {
        String[] array = new String[]{"First Element"};
        test t = new test();
        t.x = "New String";
        String comment1 = t.unsan();
        String comment2 = t.san();
        System.out.println(t.x);
        System.out.println(array[0]);
    }
}

