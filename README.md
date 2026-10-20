# Backend Atlas

Backend Atlas is a minimal read-only repository scanner for local codebases. It inspects a selected repository without executing its scripts or modifying any files, and reports likely issues such as missing relative imports and project-root structure problems.

## Features

- Validates local repository paths
- Rejects non-existent and non-directory inputs
- Excludes git metadata, dependency folders, virtual environments, build output, and secret files from scans
- Detects project roots using common manifests
- Static analysis for missing relative imports in JavaScript and TypeScript files
- FastAPI backend + React + TypeScript dashboard

## Project structure

- `backend/` – Python + FastAPI service
- `frontend/` – React + TypeScript + Vite app
- `backend/tests/` – pytest coverage for scanner logic

## Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend setup

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

## Backend tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```

## Frontend build

```bash
cd frontend
npm run build
```

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
  "repository_path": "/path/to/repository",
  "project_roots": ["package.json"],
  "findings": [
    {
      "id": "scan-123",
      "severity": "warning",
      "rule_id": "RELATIVE_IMPORT_MISSING",
      "file_path": "src/main.js",
      "line_number": 2,
      "evidence": "import '../missing';",
      "explanation": "This is a likely issue, not a confirmed runtime defect.",
      "suggested_fix": "Update the import to a real relative target or add the missing file."
    }
  ]
}
```

## Read-only scanning policy

This project intentionally performs static analysis only:

- no repository scripts are executed
- no dependencies are installed inside the target project
- no files are modified
- no AI APIs are used
- no package managers are invoked against the scanned repository

## Notes

Static analysis can suggest likely problems, but it cannot confirm runtime issues without execution. Findings are therefore reported as probable issues rather than confirmed defects.
