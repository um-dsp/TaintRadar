public class ReachingDef {
    public static void main(String[] args) {
        int x = 0;
        int y = x + 1;
        System.out.println(y);
        while (y < 10) {
            if (y < 5) {
                x = 1;
            } else {
                x = 2;
            }
        }
        System.out.println(x);  
    }
}