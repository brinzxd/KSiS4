import java.io.IOException;

public class Main {

    private static final int DEFAULT_PORT = 8888;
    private static final String DEFAULT_BIND_IP = "127.0.0.1";
    private static final String DEFAULT_BLACKLIST_FILE = "src/main/java/BlackList.txt";

    public static void main(String[] args) {
        launch();
    }

    private static void launch() {
        try {
            Proxy server = new Proxy(
                    DEFAULT_PORT,
                    DEFAULT_BLACKLIST_FILE,
                    DEFAULT_BIND_IP
            );
            server.start();
        } catch (IOException ex) {
            System.err.println("Не удалось запустить HTTP-прокси: " + ex.getMessage());
        }
    }
}