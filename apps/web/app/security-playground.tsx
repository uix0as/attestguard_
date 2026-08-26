"use client";

import { FormEvent, useMemo, useState } from "react";

interface Finding {
  type: string;
  start: number;
  end: number;
  confidence: number;
  source: string;
  credential: boolean;
}

interface GatewayResponse {
  choices: Array<{ message: { content: string } }>;
  security: {
    request_id: string;
    detected_entities: Finding[];
    data_class: string;
    policy: { action: string; reasonCode: string; policyId: string };
    requested_provider: string;
    selected_provider: string;
    routing_reason: string;
    provider_trust_level: string;
    provider_simulated: boolean;
    attestation: { status: string; label: string; verified: boolean };
    sanitized_prompt: string;
    sanitized_response: string;
    authorized_response: string;
  };
}

interface ErrorResponse {
  error?: { message?: string; code?: string; request_id?: string };
}

export function SecurityPlayground({ demoMode }: { demoMode: boolean }) {
  const [apiUrl, setApiUrl] = useState("http://localhost:8080");
  const [token, setToken] = useState("");
  const [prompt, setPrompt] = useState(
    "김민수 고객의 전화번호 010-1234-5678로 배송 지연 안내를 작성해 줘.",
  );
  const [result, setResult] = useState<GatewayResponse>();
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);

  const entitySummary = useMemo(() => {
    if (!result) return "No scan yet";
    return `${result.security.detected_entities.length} finding${result.security.detected_entities.length === 1 ? "" : "s"}`;
  }, [result]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    setResult(undefined);
    try {
      const response = await fetch(
        `${apiUrl.replace(/\/$/, "")}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
            "x-request-id": crypto.randomUUID(),
          },
          body: JSON.stringify({
            model: "mock-external",
            messages: [{ role: "user", content: prompt }],
            session_id: crypto.randomUUID(),
            purpose: "security-console-demo",
          }),
        },
      );
      const payload = (await response.json()) as
        GatewayResponse | ErrorResponse;
      if (!response.ok || "error" in payload) {
        const failure = payload as ErrorResponse;
        throw new Error(
          `${failure.error?.code ?? "AG_REQUEST_FAILED"} — ${failure.error?.message ?? "Request failed safely"}`,
        );
      }
      setResult(payload as GatewayResponse);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "The request failed safely",
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="playgroundGrid">
      <form className="requestPanel" onSubmit={submit}>
        <div className="panelTitle">
          <div>
            <h3>Request configuration</h3>
            <p>Sent to the local AttestGuard gateway</p>
          </div>
        </div>
        <label>
          Gateway URL
          <input
            value={apiUrl}
            onChange={(event) => setApiUrl(event.target.value)}
            inputMode="url"
          />
        </label>
        <label>
          Development JWT
          <input
            value={token}
            onChange={(event) => setToken(event.target.value)}
            type="password"
            autoComplete="off"
            placeholder="Paste a short-lived synthetic token"
            required
          />
        </label>
        <label>
          Test prompt
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            rows={7}
            required
          />
        </label>
        {!demoMode && (
          <p className="productionNote">
            Production mode: the result view will not repeat the raw input.
          </p>
        )}
        <button type="submit" disabled={pending}>
          {pending ? "Evaluating…" : "Run security pipeline"}
        </button>
      </form>

      <div className="resultPanel" aria-live="polite">
        <div className="panelTitle">
          <div>
            <h3>Inspection result</h3>
            <p>{entitySummary}</p>
          </div>
        </div>
        {!result && !error && (
          <div className="emptyState">
            <div className="emptyIcon" aria-hidden="true">
              ⌁
            </div>
            <strong>Awaiting a request</strong>
            <p>
              Detection findings, policy decisions, and routing evidence will
              appear here.
            </p>
          </div>
        )}
        {error && (
          <div className="blocked">
            <strong>Request blocked or unavailable</strong>
            <p>{error}</p>
          </div>
        )}
        {result && (
          <div className="trace">
            <div className="decisionRow">
              <span>Decision</span>
              <strong>{result.security.policy.action}</strong>
            </div>
            <div className="decisionRow">
              <span>Data class</span>
              <strong>{result.security.data_class}</strong>
            </div>
            <div className="decisionRow">
              <span>Route</span>
              <strong>
                {result.security.requested_provider} →{" "}
                {result.security.selected_provider}
              </strong>
            </div>
            <div className="decisionRow">
              <span>Trust</span>
              <strong>
                {result.security.provider_trust_level}
                {result.security.provider_simulated ? " · SIMULATED" : ""}
              </strong>
            </div>
            <div className="decisionRow warning">
              <span>Attestation</span>
              <strong>{result.security.attestation.label}</strong>
            </div>

            <div className="findingList">
              <h4>Detected entities</h4>
              {result.security.detected_entities.map((finding, index) => (
                <div key={`${finding.type}-${finding.start}-${index}`}>
                  <span>{finding.type}</span>
                  <code>
                    {Math.round(finding.confidence * 100)}% · {finding.source} ·
                    [{finding.start}, {finding.end})
                  </code>
                </div>
              ))}
            </div>

            <ResultBlock
              label="Sanitized provider input"
              value={result.security.sanitized_prompt}
            />
            <ResultBlock
              label="Sanitized model response"
              value={result.security.sanitized_response}
            />
            <ResultBlock
              label="Authorized response"
              value={result.security.authorized_response}
            />
            {demoMode && (
              <ResultBlock
                label="Demo-only original input"
                value={prompt}
                danger
              />
            )}
            <p className="requestId">
              Request {result.security.request_id} ·{" "}
              {result.security.policy.reasonCode}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultBlock({
  label,
  value,
  danger = false,
}: {
  label: string;
  value: string;
  danger?: boolean;
}) {
  return (
    <div className={`resultBlock ${danger ? "danger" : ""}`}>
      <h4>{label}</h4>
      <pre>{value}</pre>
    </div>
  );
}
