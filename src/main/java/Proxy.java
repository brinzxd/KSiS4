import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class Proxy {

    private static final int CONNECTION_QUEUE_SIZE = 50;

    private final int listenPort;
    private final InetAddress listenAddress;
    private final BlackList blackList;

    public Proxy(int listenPort, String blacklistFile, String bindIp) throws IOException {
        this.listenPort = listenPort;
        this.listenAddress = InetAddress.getByName(bindIp);
        this.blackList = new BlackList(blacklistFile);
    }

    public void start() throws IOException {
        try (ServerSocket listener = createServerSocket()) {
            printStartupMessage();

            while (!listener.isClosed()) {
                Socket client = listener.accept();
                launchClientHandler(client);
            }
        }
    }

    private ServerSocket createServerSocket() throws IOException {
        return new ServerSocket(listenPort, CONNECTION_QUEUE_SIZE, listenAddress);
    }

    private void launchClientHandler(Socket clientSocket) {
        Runnable task = new ClientHandler(clientSocket, blackList);
        Thread worker = new Thread(task, "proxy-client-" + clientSocket.getPort());
        worker.start();
    }

    private void printStartupMessage() {
        System.out.println("Прокси запущен. Адрес:  " +
                listenAddress.getHostAddress() + ":" + listenPort);
    }
}