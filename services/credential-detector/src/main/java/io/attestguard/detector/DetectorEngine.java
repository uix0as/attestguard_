package io.attestguard.detector;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DetectorEngine {
    public record Finding(String type, int start, int end, double confidence, String source) {}

    private record Detector(String type, Pattern pattern, double confidence) {}

    private static final List<Detector> DETECTORS = List.of(
            detector("PRIVATE_KEY", "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", 1.0),
            detector("AWS_ACCESS_KEY", "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b", 0.99),
            detector("GITHUB_TOKEN", "\\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,255}\\b", 0.99),
            detector("JWT", "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b", 0.98),
            detector("DATABASE_URI", "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?):\\/\\/[^\\s:/]+:[^\\s@]+@[^\\s]+", 0.99),
            detector("AWS_SECRET_KEY", "(?:aws_secret_access_key|aws_secret_key)\\s*[:=]\\s*['\"]?[A-Za-z0-9/+]{40}['\"]?", 0.99),
            detector("PASSWORD_IN_CONFIG", "(?:password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"\\r\\n]{8,}['\"]", 0.95),
            detector("OAUTH_TOKEN", "(?:refresh_token|oauth_token)\\s*[:=]\\s*['\"]?[A-Za-z0-9._~-]{20,}['\"]?", 0.96)
    );

    public List<Finding> scan(String text) {
        if (text == null) throw new IllegalArgumentException("text is required");
        if (text.length() > 32_768) throw new IllegalArgumentException("text exceeds the scan limit");
        List<Finding> findings = new ArrayList<>();
        for (Detector detector : DETECTORS) {
            Matcher matcher = detector.pattern().matcher(text);
            while (matcher.find()) {
                findings.add(new Finding(
                        detector.type(), matcher.start(), matcher.end(), detector.confidence(), "java-secret-scanner"));
            }
        }
        findings.sort(Comparator.comparingInt(Finding::start).thenComparingInt(Finding::end));
        return List.copyOf(findings);
    }

    private static Detector detector(String type, String regex, double confidence) {
        return new Detector(type, Pattern.compile(regex, Pattern.CASE_INSENSITIVE), confidence);
    }
}
