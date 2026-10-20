# Backend Atlas

Backend Atlas Stage 1 is a read-only repository scanner for local codebases. It discovers common project manifests and reports likely missing JavaScript/TypeScript relative imports without executing repository code or modifying files.

## Features

- Validates local repository paths
- Rejects non-existent and non-directory inputs
- Excludes git metadata, dependency folders, virtual environments, build output, and secret files from scans
- Detects project roots using common manifests
- Static analysis for missing relative imports in JavaScript and TypeScript files
- FastAPI backend

## Project structure

- `backend/` – Python + FastAPI service
- `backend/tests/` – pytest coverage for scanner logic
- `frontend/` – React + TypeScript + Vite interface

## Prerequisites

- Python 3.10 or newer on a POSIX platform with `O_NOFOLLOW`, descriptor-relative `open` (`dir_fd`), and `/proc/self/fd` support for secure scans
- Node.js 20.19 or newer (or 22.12 or newer) and npm
- A repository directory that is inside the configured `BACKEND_ATLAS_ALLOWED_ROOTS`

## Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p "$HOME/projects"
export BACKEND_ATLAS_ALLOWED_ROOTS="$HOME/projects"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

`BACKEND_ATLAS_ALLOWED_ROOTS` is required. Set it to one or more existing directories separated by `:` on Linux/macOS (or `;` on Windows). A scan is rejected unless its repository is inside one of these roots. Windows path-list syntax is accepted as configuration syntax only; it does not mean Windows scanning is supported. Secure source scanning currently requires POSIX `O_NOFOLLOW`, descriptor-relative file opening (`dir_fd`), and file-descriptor path validation via `/proc/self/fd`. Unsupported platforms, including Windows environments without these capabilities, fail closed and cannot perform secure scans. The development server binds only to loopback; CORS is limited to the two local Vite origins, but CORS is not network access control.

Do not set the allowed root to a broader directory than needed. The service does not execute target code, install target dependencies, invoke package managers, or write to scanned repositories.

## Backend tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```

## Frontend setup

Start the backend as described above, then in another terminal run:

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

Open the Vite URL printed in the terminal. During development, Vite proxies `/api` and `/health` to `http://127.0.0.1:8000`, so the browser uses its same origin and the backend can remain loopback-only with its existing CORS policy. To connect directly to a different backend deployment, set `VITE_API_BASE_URL` before starting Vite; that deployment must permit the frontend origin through its own CORS configuration. The browser submits the entered path to the backend; it does not grant authorization or access files itself.

Build the frontend for production with:

```bash
cd frontend
npm run build
```

## GitHub Codespaces

The checked-in `.devcontainer/devcontainer.json` forwards ports `5174` and `8000` and opens the frontend when port `5174` is forwarded. Start the backend using the backend setup command above, then start Vite using the frontend setup command above. Vite listens on `0.0.0.0:5174` for port forwarding; the backend remains bound to `127.0.0.1:8000`.

In VS Code, open the **Ports** tab and choose **Open in Browser** for port `5174`. Use the forwarded URL shown there; `http://localhost:5174` on your own computer is not the Codespaces URL. The frontend uses the Vite proxy, so the browser does not need direct access to backend port `8000`.

## API contract

Endpoint:

```http
POST /api/scan
Content-Type: application/json
```

Request body:

```json
{
  "repository_path": "/path/to/repository"
}
```

Response:

```json
{
  "repository_path": "/home/user/projects/sample",
  "project_roots": ["package.json", "src/pyproject.toml"],
  "findings": [
    {
      "id": "scan-123",
      "severity": "warning",
      "rule_id": "RELATIVE_IMPORT_MISSING",
      "file_path": "src/main.js",
      "line_number": 2,
      "evidence": "import '../missing';",
      "explanation": "This is a likely issue, not a confirmed runtime failure.",
      "suggested_fix": "Update the import to a real relative target or add the missing file."
    }
  ]
}
```

The health endpoint is `GET /health`. To request a scan, send the JSON body above to `POST /api/scan`. Findings use repository-relative file paths. Manifest discovery includes `package.json`, `pyproject.toml`, `requirements.txt`, `Cargo.toml`, `go.mod`, `pom.xml`, and common Gradle build/settings files.

## Read-only scanning policy

This project intentionally performs static analysis only:

- no repository scripts are executed
- no dependencies are installed inside the target project
- no scanned files are modified
- no AI APIs are used
- no package managers are invoked against the scanned repository
- symlinked repository paths are rejected; symlinked files and directories are not scanned
- common generated/dependency directories and secret-like files are excluded

## Notes

Import recognition uses lightweight lexical and regex-based heuristics. It handles common static, dynamic, and `require` imports, including multiline declarations, but regex-based parsing cannot fully implement the JavaScript/TypeScript grammar. Findings are likely issues, not confirmed runtime failures. The scanner does not resolve package imports, aliases, conditional exports, or compiler-specific path mappings.

The scanner checks resolved paths and does not follow symlinks during source reads. It does not establish that a file inside the approved repository, if hard-linked, has no other links elsewhere.

Last verified results: Linux Codespaces, Python 3.14.2, and 19 backend tests passing. These describe the last verified environment and test run, not guarantees for other platforms, Python versions, or environments.
