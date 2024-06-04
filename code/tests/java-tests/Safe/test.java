import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;

public class test {
    // <init> method
    String x;
    String message;
    Connection connection;

    public test() {
        this.x = "Hello";
        this.message = "Hey there!";
        this.connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "root", "password");
        this.x = "Original value: " + this.x;
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                this.x = this.x + " .";
            }
            else {
                this.x = this.x + " !";
            }
        }    
    }

    public void change() {
        this.x = "Changed value: " + this.x;
    }

    public void dontChange() {
        System.out.println("Original value: " + this.x);
    }

    public static void change(test o, String message) {
        o.x = message + o.x;
        System.out.println(o.x);
    }

    public String unsan(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        return comment;
    }

    public String printComment(String comment) {
        System.out.println(comment);
    }

    public String san(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        comment = connection.escape(comment);
        return comment;
    }

    public static void main(String[] args) {
        // String[] array = new String[]{"First Element"};
        test t = new test();
        t.change();
        test.change(t, "Original value: ");
        println(t.x);
        test t = new test();
        t.x = "Original value: " + t.x;
        t.x = t.x + " .";
        String comment1 = t.unsan();
        String comment2 = t.san();
        // System.out.println(t.x);
        // System.out.println(array[0]);
    }
}

