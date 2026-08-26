package io.attestguard.detector;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;

public final class Main {
    private static final int MAX_BODY_BYTES = 131_072;

    private Main() {}

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8090"));
        DetectorEngine engine = new DetectorEngine();
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 32);
        server.createContext("/health", exchange -> send(exchange, 200, "{\"status\":\"ok\"}"));
        server.createContext("/scan", exchange -> handleScan(exchange, engine));
        server.setExecutor(Executors.newFixedThreadPool(
                Math.max(2, Runtime.getRuntime().availableProcessors())));
        server.start();
        System.out.println("Java credential detector listening on port " + port + " (raw values are never logged)");
    }

    private static void handleScan(HttpExchange exchange, DetectorEngine engine) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }
        byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (body.length > MAX_BODY_BYTES) {
            send(exchange, 413, "{\"error\":\"payload_too_large\"}");
            return;
        }
        try {
            List<DetectorEngine.Finding> findings = engine.scan(new String(body, StandardCharsets.UTF_8));
            send(exchange, 200, toJson(findings));
        } catch (IllegalArgumentException ignored) {
            send(exchange, 400, "{\"error\":\"invalid_scan_input\"}");
        }
    }

    private static String toJson(List<DetectorEngine.Finding> findings) {
        StringBuilder json = new StringBuilder("{\"findings\":[");
        for (int index = 0; index < findings.size(); index++) {
            DetectorEngine.Finding finding = findings.get(index);
            if (index > 0) json.append(',');
            json.append("{\"type\":\"").append(finding.type())
                    .append("\",\"start\":").append(finding.start())
                    .append(",\"end\":").append(finding.end())
                    .append(",\"confidence\":").append(finding.confidence())
                    .append(",\"source\":\"").append(finding.source()).append("\"}");
        }
        return json.append("]}").toString();
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, payload.length);
        try (var output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }
}
