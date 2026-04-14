import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class Http {

    private final String method;
    private final String originalUrl;
    private final String requestPath;
    private final String version;
    private final List<String> headerLines;
    private final String targetHost;
    private final int targetPort;
    private final int bodyLength;

    private Http(String method,
                            String originalUrl,
                            String requestPath,
                            String version,
                            List<String> headerLines,
                            String targetHost,
                            int targetPort,
                            int bodyLength) {
        this.method = method;
        this.originalUrl = originalUrl;
        this.requestPath = requestPath;
        this.version = version;
        this.headerLines = headerLines;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.bodyLength = bodyLength;
    }

    public static Http parse(String requestLine, List<String> rawHeaders) {
        ParsedStartLine startLine = parseStartLine(requestLine);
        if (startLine == null) {
            return null;
        }

        HeaderData headerData = extractHeaderData(rawHeaders);

        try {
            UrlData urlData = normalizeUrlAndPath(startLine.uri, headerData.host, headerData.port);
            List<String> finalHeaders = ensureHostHeader(rawHeaders, urlData.host, urlData.portFromUrl);

            return new Http(
                    startLine.method,
                    urlData.fullUrl,
                    urlData.path,
                    startLine.version,
                    finalHeaders,
                    urlData.host,
                    urlData.effectivePort,
                    headerData.contentLength
            );
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static ParsedStartLine parseStartLine(String line) {
        if (line == null) {
            return null;
        }

        String[] tokens = line.split(" ");
        if (tokens.length < 3) {
            return null;
        }

        return new ParsedStartLine(tokens[0], tokens[1], tokens[2]);
    }

    private static HeaderData extractHeaderData(List<String> headers) {
        String host = null;
        int port = 80;
        int contentLength = 0;

        for (String header : headers) {
            String lower = header.toLowerCase();

            if (lower.startsWith("host:")) {
                HostPort hp = parseHostHeader(header);
                host = hp.host;
                if (hp.port != null) {
                    port = hp.port;
                }
            } else if (lower.startsWith("content-length:")) {
                contentLength = parseContentLength(header);
            }
        }

        return new HeaderData(host, port, contentLength);
    }

    //extracting host and port
    private static HostPort parseHostHeader(String header) {
        String value = header.substring("host:".length()).trim();
        String host = value;
        Integer port = null;

        int colonPos = value.indexOf(':');
        if (colonPos != -1) {
            host = value.substring(0, colonPos).trim();
            try {
                port = Integer.parseInt(value.substring(colonPos + 1).trim());
            } catch (NumberFormatException ignored) {
                // оставляем port = null
            }
        }

        return new HostPort(host, port);
    }

    private static int parseContentLength(String header) {
        String value = header.substring("content-length:".length()).trim();
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static UrlData normalizeUrlAndPath(String uri, String hostFromHeader, int portFromHeader)
            throws MalformedURLException {

        String fullUrl;
        String path;
        String host = hostFromHeader;
        int port = portFromHeader;
        Integer portFromUrl = null;

        if (uri.startsWith("http://") || uri.startsWith("https://")) {
            URL parsed = new URL(uri);
            fullUrl = uri;
            path = parsed.getFile().isEmpty() ? "/" : parsed.getFile();

            if (host == null) {
                host = parsed.getHost();
            }

            if (parsed.getPort() != -1) {
                portFromUrl = parsed.getPort();
                if (port == 80) {
                    port = parsed.getPort();
                }
            }
        } else {
            if (host == null) {
                return null;
            }
            fullUrl = "http://" + host + uri;
            path = uri;
        }

        if (host == null) {
            return null;
        }

        return new UrlData(fullUrl, path, host, port, portFromUrl);
    }

    private static List<String> ensureHostHeader(List<String> originalHeaders,
                                                 String host,
                                                 Integer portFromUrl) {
        boolean hasHostHeader = false;
        List<String> result = new ArrayList<>(originalHeaders.size() + 1);

        for (String header : originalHeaders) {
            result.add(header);
            if (header.toLowerCase().startsWith("host:")) {
                hasHostHeader = true;
            }
        }

        if (!hasHostHeader) {
            String hostHeader = "Host: " + host
                    + (portFromUrl != null ? (":" + portFromUrl) : "");
            result.add(hostHeader);
        }

        return result;
    }

    public String getMethod() {
        return method;
    }

    public String getFullUrl() {
        return originalUrl;
    }

    public String getPath() {
        return requestPath;
    }

    public String getHttpVersion() {
        return version;
    }

    public List<String> getHeaders() {
        return headerLines;
    }

    public String getHost() {
        return targetHost;
    }

    public int getPort() {
        return targetPort;
    }

    public int getContentLength() {
        return bodyLength;
    }

    private record ParsedStartLine(String method, String uri, String version) {}

    private record HeaderData(String host, int port, int contentLength) {}

    private record HostPort(String host, Integer port) {}

    private record UrlData(String fullUrl,
                           String path,
                           String host,
                           int effectivePort,
                           Integer portFromUrl) {}
}