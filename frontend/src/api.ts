export interface ScanFinding {
  id?: string;
  severity?: string;
  rule_id?: string;
  file_path?: string;
  line_number?: number;
  evidence?: string;
  explanation?: string;
  suggested_fix?: string;
}

export interface ScanResponse {
  repository_path: string;
  project_roots: string[];
  findings: ScanFinding[];
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

export class ApiRequestError extends Error {
  constructor(public readonly status: number) {
    super(`Backend request failed with status ${status}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(
  value: Record<string, unknown>,
  key: string,
): string | undefined {
  const field = value[key];
  if (field === undefined || field === null) return undefined;
  if (typeof field !== "string") throw new Error("Malformed scan response");
  return field;
}

function parseFinding(value: unknown): ScanFinding {
  if (!isRecord(value)) throw new Error("Malformed scan response");
  const lineNumber = value.line_number;
  if (
    lineNumber !== undefined &&
    lineNumber !== null &&
    (typeof lineNumber !== "number" || !Number.isInteger(lineNumber))
  ) {
    throw new Error("Malformed scan response");
  }

  return {
    id: optionalString(value, "id"),
    severity: optionalString(value, "severity"),
    rule_id: optionalString(value, "rule_id"),
    file_path: optionalString(value, "file_path"),
    line_number: typeof lineNumber === "number" ? lineNumber : undefined,
    evidence: optionalString(value, "evidence"),
    explanation: optionalString(value, "explanation"),
    suggested_fix: optionalString(value, "suggested_fix"),
  };
}

function parseScanResponse(value: unknown): ScanResponse {
  if (
    !isRecord(value) ||
    typeof value.repository_path !== "string" ||
    !Array.isArray(value.project_roots) ||
    !value.project_roots.every((root) => typeof root === "string") ||
    !Array.isArray(value.findings)
  ) {
    throw new Error("Malformed scan response");
  }

  return {
    repository_path: value.repository_path,
    project_roots: value.project_roots,
    findings: value.findings.map(parseFinding),
  };
}

export async function checkHealth(signal: AbortSignal): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, { signal });
    if (!response.ok) return false;
    const body: unknown = await response.json();
    return isRecord(body) && body.status === "ok";
  } catch {
    return false;
  }
}

export async function scanRepository(
  repositoryPath: string,
  signal: AbortSignal,
): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repository_path: repositoryPath }),
    signal,
  });

  if (!response.ok) throw new ApiRequestError(response.status);

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error("Malformed scan response");
  }
  return parseScanResponse(body);
}