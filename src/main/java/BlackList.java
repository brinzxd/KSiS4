import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class BlackList {

    private final Set<String> blockedHosts = new HashSet<>();
    private final Set<String> blockedUrls = new HashSet<>();

    public BlackList(String filePath) {
        loadRules(filePath);
    }

    private void loadRules(String filePath) {
        File source = new File(filePath);

        if (!source.exists()) {
            System.out.println("Не найден файл со списком блокировки: " + filePath);
            return;
        }

        int loadedCount = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(source))) {
            String row;

            while ((row = reader.readLine()) != null) {
                String normalized = row.trim().toLowerCase();

                if (normalized.isEmpty() || normalized.startsWith("#")) {
                    continue;
                }

                if (isUrlRule(normalized)) {
                    blockedUrls.add(normalized);
                } else {
                    blockedHosts.add(normalized);
                }

                loadedCount++;
            }

            System.out.println("Загружено правил блокировки: " + loadedCount);
        } catch (IOException ex) {
            System.err.println("Не удалось прочитать файл блокировки: " + ex.getMessage());
        }
    }

    public boolean isForbidden(String requestUrl, String requestHost) {
        if (requestUrl == null || requestHost == null) {
            return false;
        }

        String normalizedUrl = requestUrl.toLowerCase();
        String normalizedHost = requestHost.toLowerCase();

        if (matchesUrlRule(normalizedUrl)) {
            return true;
        }

        return matchesHostRule(normalizedHost);
    }

    private boolean matchesUrlRule(String url) {
        for (String blockedUrl : blockedUrls) {
            if (url.startsWith(blockedUrl)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesHostRule(String host) {
        if (blockedHosts.contains(host)) {
            return true;
        }

        for (String blockedHost : blockedHosts) {
            if (host.endsWith("." + blockedHost)) {
                return true;
            }
        }

        return false;
    }

    private boolean isUrlRule(String value) {
        return value.startsWith("http://") || value.startsWith("https://");
    }
}