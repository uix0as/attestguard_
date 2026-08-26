import { SecurityPlayground } from "./security-playground";

export default function Home() {
  const demoMode = process.env.NEXT_PUBLIC_DEMO_MODE === "true";
  return (
    <div className="appFrame">
      <aside className="sidebar">
        <div className="brand">
          <span className="brandMark" aria-hidden="true">
            A
          </span>
          <div>
            <strong>AttestGuard</strong>
            <small>Security gateway</small>
          </div>
        </div>

        <nav aria-label="Primary navigation">
          <p>Workspace</p>
          <a href="#overview">
            <span aria-hidden="true">⌂</span>Overview
          </a>
          <a className="navActive" href="#playground">
            <span aria-hidden="true">⌁</span>Prompt inspector
          </a>
          <a href="#events">
            <span aria-hidden="true">◇</span>Security events
          </a>
          <a href="#policies">
            <span aria-hidden="true">≡</span>Policies
          </a>
          <p>Infrastructure</p>
          <a href="#providers">
            <span aria-hidden="true">□</span>Providers
          </a>
          <a href="#attestation">
            <span aria-hidden="true">✓</span>Attestation
          </a>
        </nav>

        <div className="sidebarNotice">
          <span>DEV</span>
          <div>
            <strong>Local environment</strong>
            <p>Ephemeral keys and mock providers</p>
          </div>
        </div>
      </aside>

      <div className="appBody">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Security</span>
            <b>/</b>
            <strong>Prompt inspector</strong>
          </div>
          <div className="topbarActions">
            <span className="environment">
              <i />
              Gateway available
            </span>
            <button
              className="avatar"
              type="button"
              aria-label="Open user menu"
            >
              SA
            </button>
          </div>
        </header>

        <main className="mainContent">
          <section className="pageHeading" id="overview">
            <div>
              <h1>Prompt inspector</h1>
              <p>
                See exactly how a request is detected, transformed, and routed
                before it reaches a model.
              </p>
            </div>
            <a
              className="docsLink"
              href="https://github.com/uix0as/attestguard_"
            >
              View API docs ↗
            </a>
          </section>

          <section className="statusStrip" aria-label="Environment status">
            <StatusItem
              label="Policy"
              value="default.yaml · v1"
              state="normal"
            />
            <StatusItem
              label="Credential detector"
              value="Java · required"
              state="ready"
            />
            <StatusItem
              label="Provider mode"
              value="Local mock"
              state="normal"
            />
            <StatusItem
              label="Attestation"
              value="SIMULATED — NOT HARDWARE-BACKED"
              state="warning"
            />
          </section>

          <div className="attestationNotice" id="attestation">
            <strong>Attestation is simulated</strong>
            <span>
              Not hardware-backed. This environment cannot satisfy an
              ATTESTED_TEE policy or issue a hardware-required key lease.
            </span>
          </div>

          <section id="playground" className="workspace">
            <div className="sectionHeading">
              <div>
                <h2>Inspect a request</h2>
                <p>
                  Use synthetic data only. The gateway returns safe metadata and
                  reason codes.
                </p>
              </div>
              <span className="sessionLabel">Current session</span>
            </div>
            <SecurityPlayground demoMode={demoMode} />
          </section>
        </main>
      </div>
    </div>
  );
}

function StatusItem({
  label,
  value,
  state,
}: {
  label: string;
  value: string;
  state: "ready" | "normal" | "warning";
}) {
  return (
    <div className="statusItem">
      <span className={`statusDot ${state}`} />
      <div>
        <small>{label}</small>
        <strong>{value}</strong>
      </div>
    </div>
  );
}
