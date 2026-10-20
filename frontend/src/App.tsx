import { useEffect, useState } from "react";

import { ApiRequestError, checkHealth, scanRepository } from "./api";
import type { ScanFinding, ScanResponse } from "./api";

type HealthState = "checking" | "online" | "offline";
type ScanState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "results"; data: ScanResponse }
  | { kind: "error"; message: string };

function errorMessage(error: unknown): string {
  if (error instanceof ApiRequestError) {
    if (error.status === 400) {
      return "The backend could not scan this path. Confirm it exists and is a directory.";
    }
    if (error.status === 403) {
      return "This path is not authorized. Ask the backend operator to include it in BACKEND_ATLAS_ALLOWED_ROOTS.";
    }
    if (error.status === 500) {
      return "The backend is not configured to scan yet. The operator must set BACKEND_ATLAS_ALLOWED_ROOTS.";
    }
    if (error.status === 503) {
      return "Secure scanning is unavailable on the backend platform.";
    }
    return `The backend returned an unexpected response (${error.status}).`;
  }
  if (error instanceof TypeError) {
    return "Could not reach the backend. Check that it is running and that the API URL is correct.";
  }
  if (error instanceof Error && error.message === "Malformed scan response") {
    return "The backend returned an unreadable scan response.";
  }
  return "The scan could not be completed. Try again.";
}

function severityClass(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
    case "error":
      return "severity severity--high";
    case "warning":
      return "severity severity--warning";
    case "info":
      return "severity severity--info";
    default:
      return "severity";
  }
}

function FindingRow({ finding, index }: { finding: ScanFinding; index: number }) {
  return (
    <article className="finding" key={`${finding.id ?? "finding"}-${index}`}>
      <div className="finding__topline">
        {finding.severity && (
          <span className={severityClass(finding.severity)}>{finding.severity}</span>
        )}
        {finding.rule_id && <span className="finding__rule">{finding.rule_id}</span>}
        {finding.file_path && (
          <span className="finding__location">
            <code>{finding.file_path}</code>
            {finding.line_number !== undefined && (
              <span> : {finding.line_number}</span>
            )}
          </span>
        )}
      </div>
      {finding.evidence && <pre className="finding__evidence">{finding.evidence}</pre>}
      {finding.explanation && <p className="finding__explanation">{finding.explanation}</p>}
      {finding.suggested_fix && (
        <p className="finding__fix">
          <span>Suggested fix</span> {finding.suggested_fix}
        </p>
      )}
    </article>
  );
}

export default function App() {
  const [repositoryPath, setRepositoryPath] = useState("");
  const [health, setHealth] = useState<HealthState>("checking");
  const [scanState, setScanState] = useState<ScanState>({ kind: "idle" });
  const [inputError, setInputError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void checkHealth(controller.signal).then((available) => {
      setHealth(available ? "online" : "offline");
    });
    return () => controller.abort();
  }, []);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (scanState.kind === "loading") return;

    const normalizedPath = repositoryPath.trim();
    if (!normalizedPath) {
      setInputError("Enter a local repository path.");
      return;
    }

    setInputError("");
    setScanState({ kind: "loading" });
    const controller = new AbortController();
    try {
      const data = await scanRepository(normalizedPath, controller.signal);
      setHealth("online");
      setScanState({ kind: "results", data });
    } catch (error) {
      if (error instanceof ApiRequestError) setHealth("online");
      else if (error instanceof TypeError) setHealth("offline");
      setScanState({ kind: "error", message: errorMessage(error) });
    }
  }

  const isLoading = scanState.kind === "loading";
  const result = scanState.kind === "results" ? scanState.data : undefined;

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#main" aria-label="Backend Atlas home">
          <span className="brand__mark" aria-hidden="true">A</span>
          <span>Backend Atlas</span>
        </a>
        <div className={`connection connection--${health}`} role="status">
          <span className="connection__dot" aria-hidden="true" />
          {health === "checking" ? "Checking backend" : health === "online" ? "Backend available" : "Backend unavailable"}
        </div>
      </header>

      <main id="main" className="main-content">
        <section className="intro" aria-labelledby="page-title">
          <p className="eyebrow">READ-ONLY REPOSITORY INSPECTION</p>
          <h1 id="page-title">Repository scan</h1>
          <p className="intro__copy">
            Discover project manifests and review likely missing JavaScript or TypeScript relative imports.
          </p>
        </section>

        <section className="scan-section" aria-labelledby="scan-heading">
          <div className="section-heading">
            <span className="section-heading__index">01</span>
            <h2 id="scan-heading">Choose a repository</h2>
          </div>
          <form className="scan-form" onSubmit={handleSubmit} noValidate>
            <label htmlFor="repository-path">Local repository path</label>
            <div className="scan-form__row">
              <input
                id="repository-path"
                name="repository_path"
                type="text"
                value={repositoryPath}
                onChange={(event) => {
                  setRepositoryPath(event.target.value);
                  setInputError("");
                }}
                placeholder="/workspaces/my-project"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(inputError)}
                aria-describedby="path-help path-error"
                disabled={isLoading}
              />
              <button type="submit" disabled={isLoading}>
                {isLoading ? "Scanning…" : "Scan repository"}
              </button>
            </div>
            <p id="path-help" className="form-help">
              The backend scans only paths inside its configured <code>BACKEND_ATLAS_ALLOWED_ROOTS</code>. This field does not grant access.
            </p>
            <p id="path-error" className="input-error" aria-live="polite">
              {inputError}
            </p>
          </form>
        </section>

        <section className="results-section" aria-labelledby="results-heading" aria-live="polite">
          <div className="section-heading section-heading--results">
            <span className="section-heading__index">02</span>
            <h2 id="results-heading">Scan results</h2>
            {result && (
              <span className="result-summary">
                {result.findings.length} potential {result.findings.length === 1 ? "issue" : "issues"}
              </span>
            )}
          </div>

          {scanState.kind === "idle" && (
            <div className="state-panel state-panel--idle">
              <span className="state-panel__glyph" aria-hidden="true">⌁</span>
              <p>Results will appear here after a scan.</p>
            </div>
          )}
          {scanState.kind === "loading" && (
            <div className="state-panel" role="status">
              <span className="loader" aria-hidden="true" />
              <p>Scanning the authorized repository…</p>
            </div>
          )}
          {scanState.kind === "error" && (
            <div className="state-panel state-panel--error" role="alert">
              <strong>Scan could not complete</strong>
              <p>{scanState.message}</p>
            </div>
          )}
          {result && (
            <div className="result-content">
              <div className="manifest-block">
                <div className="manifest-block__heading">
                  <h3>Project manifests</h3>
                  <span>{result.project_roots.length}</span>
                </div>
                {result.project_roots.length > 0 ? (
                  <ul className="manifest-list">
                    {result.project_roots.map((manifest) => (
                      <li key={manifest}><code>{manifest}</code></li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted-copy">No manifests discovered.</p>
                )}
              </div>

              <div className="finding-block">
                <div className="manifest-block__heading">
                  <h3>Potential issues</h3>
                  {result.findings.length > 0 && <span>{result.findings.length}</span>}
                </div>
                {result.findings.length > 0 ? (
                  <div className="finding-list">
                    {result.findings.map((finding, index) => (
                      <FindingRow finding={finding} index={index} key={`${finding.id ?? "finding"}-${index}`} />
                    ))}
                  </div>
                ) : (
                  <p className="empty-results">No likely missing relative imports were returned for this scan.</p>
                )}
              </div>
              <p className="result-footnote">
                Findings are heuristic signals, not confirmed runtime failures. Scanning does not execute or modify repository code.
              </p>
            </div>
          )}
        </section>
      </main>
      <footer className="footer">
        <span>Backend Atlas</span>
        <span>Static analysis only</span>
      </footer>
    </div>
  );
}