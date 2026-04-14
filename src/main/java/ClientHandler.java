import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ClientHandler implements Runnable {

    private static final int REMOTE_TIMEOUT = 10_000;
    private static final int STREAM_BUFFER_SIZE = 8192;

    private final Socket clientSocket;
    private final BlackList accessPolicy;

    public ClientHandler(Socket clientSocket, BlackList accessPolicy) {
        this.clientSocket = clientSocket;
        this.accessPolicy = accessPolicy;
    }

    @Override
    public void run() {
        processClient();
    }

    private void processClient() {
        try (
                InputStream browserInput = clientSocket.getInputStream();
                OutputStream browserOutput = clientSocket.getOutputStream();
                BufferedReader browserReader = new BufferedReader(new InputStreamReader(browserInput))
        ) {
            Http request = readClientRequest(browserReader);
            if (request == null) {
                return;
            }

            String requestUrl = request.getFullUrl();
            String targetHost = request.getHost();

            if (accessPolicy.isForbidden(requestUrl, targetHost)) {
                writeForbiddenPage(browserOutput, requestUrl);
                writeLog(requestUrl, 403, "Forbidden");
                return;
            }

            proxyRequest(request, browserReader, browserOutput);

        } catch (IOException ex) {
            System.err.println("Ошибка обработки соединения: " + ex.getMessage());
        } finally {
            closeClientSocket();
        }
    }

    private Http readClientRequest(BufferedReader browserReader) throws IOException {
        String startLine = browserReader.readLine();
        if (startLine == null || startLine.isBlank()) {
            return null;
        }

        List<String> headerLines = collectHeaders(browserReader);
        return Http.parse(startLine, headerLines);
    }

    private List<String> collectHeaders(BufferedReader browserReader) throws IOException {
        List<String> result = new ArrayList<>();
        String line;

        while ((line = browserReader.readLine()) != null) {
            if (line.isEmpty()) {
                break;
            }
            result.add(line);
        }

        return result;
    }

    private void proxyRequest(Http request,
                              BufferedReader browserReader,
                              OutputStream browserOutput) {
        try (Socket remoteSocket = new Socket(request.getHost(), request.getPort())) {
            remoteSocket.setSoTimeout(REMOTE_TIMEOUT);

            InputStream remoteInput = remoteSocket.getInputStream();
            OutputStream remoteOutput = remoteSocket.getOutputStream();

            writeRequestToRemote(request, browserReader, remoteOutput);
            relayServerResponse(remoteInput, browserOutput, request.getFullUrl());

        } catch (IOException ignored) {
        }
    }

    private void writeRequestToRemote(Http request,
                                      BufferedReader browserReader,
                                      OutputStream remoteOutput) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(remoteOutput), false);

        writer.print(buildRequestLine(request));
        for (String header : request.getHeaders()) {
            writer.print(header);
            writer.print("\r\n");
        }
        writer.print("\r\n");
        writer.flush();

        transferRequestBody(browserReader, writer, request.getContentLength());
    }

    private String buildRequestLine(Http request) {
        return request.getMethod() + " "
                + request.getPath() + " "
                + request.getHttpVersion() + "\r\n";
    }

    private void transferRequestBody(BufferedReader browserReader,
                                     PrintWriter writer,
                                     int contentLength) throws IOException {
        if (contentLength <= 0) {
            return;
        }

        char[] payload = new char[contentLength];
        int totalRead = 0;

        while (totalRead < contentLength) {
            int count = browserReader.read(payload, totalRead, contentLength - totalRead);
            if (count < 0) {
                break;
            }
            totalRead += count;
        }

        if (totalRead > 0) {
            writer.write(payload, 0, totalRead);
            writer.flush();
        }
    }

    private void relayServerResponse(InputStream remoteInput,
                                     OutputStream browserOutput,
                                     String requestUrl) throws IOException {
        BufferedInputStream responseInput = new BufferedInputStream(remoteInput);
        BufferedOutputStream responseOutput = new BufferedOutputStream(browserOutput);

        byte[] responseHeaders = readResponseHeaders(responseInput);
        if (responseHeaders == null) {
            return;
        }

        ResponseStatus status = extractStatus(responseHeaders);
        writeLog(requestUrl, status.code(), status.reason());

        responseOutput.write(responseHeaders);
        responseOutput.flush();

        pipeStream(responseInput, responseOutput);
    }

    private ResponseStatus extractStatus(byte[] headerBytes) {
        String headersText = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headersText.split("\r\n");

        if (lines.length == 0) {
            return new ResponseStatus(0, "Unknown");
        }

        String[] parts = lines[0].split(" ", 3);
        if (parts.length < 2) {
            return new ResponseStatus(0, "Unknown");
        }

        try {
            int code = Integer.parseInt(parts[1]);
            String reason = parts.length >= 3 ? parts[2] : "";
            return new ResponseStatus(code, reason);
        } catch (NumberFormatException ex) {
            return new ResponseStatus(0, "Unknown");
        }
    }

    private void writeLog(String url, int code, String reason) {
        System.out.println("URL: " + url + " | Response: " + code + " " + reason);
    }

    private record ResponseStatus(int code, String reason) {}

    private byte[] readResponseHeaders(InputStream input) throws IOException {
        ByteArrayOutputStream headerBytes = new ByteArrayOutputStream();
        int current;
        int matched = 0;

        while ((current = input.read()) != -1) {
            headerBytes.write(current);

            if ((matched == 0 || matched == 2) && current == '\r') {
                matched++;
            } else if ((matched == 1 || matched == 3) && current == '\n') {
                matched++;
                if (matched == 4) {
                    return headerBytes.toByteArray();
                }
            } else {
                matched = 0;
            }
        }

        return null;
    }

    private int extractStatusCode(byte[] headerBytes) {
        String headersText = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headersText.split("\r\n");

        if (lines.length == 0) {
            return 0;
        }

        String[] parts = lines[0].split(" ");
        if (parts.length < 2) {
            return 0;
        }

        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private void pipeStream(InputStream from, OutputStream to) throws IOException {
        byte[] buffer = new byte[STREAM_BUFFER_SIZE];
        int bytesRead;

        while ((bytesRead = from.read(buffer)) != -1) {
            to.write(buffer, 0, bytesRead);
            to.flush();
        }
    }

    private void writeForbiddenPage(OutputStream browserOutput, String blockedUrl) throws IOException {
        String html = "<html><body><h1>Доступ запрещён</h1><p>Запрошенный адрес в черном списке: "
                + blockedUrl + "</p></body></html>";

        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(browserOutput, StandardCharsets.UTF_8), false);

        writer.print("HTTP/1.1 403 Forbidden\r\n");
        writer.print("Content-Type: text/html; charset=UTF-8\r\n");
        writer.print("Content-Length: " + body.length + "\r\n");
        writer.print("Connection: close\r\n");
        writer.print("\r\n");
        writer.flush();

        browserOutput.write(body);
        browserOutput.flush();
    }

    private void closeClientSocket() {
        try {
            clientSocket.close();
        } catch (IOException ignored) {
        }
    }
}