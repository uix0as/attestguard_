package io.attestguard.detector;

import java.util.List;

public final class DetectorEngineTest {
    private DetectorEngineTest() {}

    public static void main(String[] args) {
        DetectorEngine engine = new DetectorEngine();
        String syntheticAccessKey = "AKIA" + "ABCDEFGHIJKLMNOP";
        String privateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";

        assertContains(engine.scan("disabled=" + syntheticAccessKey), "AWS_ACCESS_KEY");
        assertContains(engine.scan(privateKeyMarker + "\nFAKE_TEST_DATA"), "PRIVATE_KEY");
        assertContains(engine.scan("password=\"not-a-real-password\""), "PASSWORD_IN_CONFIG");
        if (!engine.scan("ordinary project number 20260826").isEmpty()) {
            throw new AssertionError("ordinary numbers must not be treated as credentials");
        }
        System.out.println("DetectorEngineTest: all assertions passed");
    }

    private static void assertContains(List<DetectorEngine.Finding> findings, String expectedType) {
        if (findings.stream().noneMatch(finding -> expectedType.equals(finding.type()))) {
            throw new AssertionError("expected finding type " + expectedType);
        }
    }
}
