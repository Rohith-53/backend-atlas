from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.scanner import ScannerSafetyError


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app)


def write_file(root: Path, relative_path: str, contents: str = "") -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_returns_manifest_and_real_unresolved_import(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    write_file(repository, "package.json", "{}")
    write_file(repository, "src/main.ts", 'import "./missing.js";')
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(tmp_path))

    response = client.post("/api/scan", json={"repository_path": str(repository)})

    assert response.status_code == 200
    body = response.json()
    assert body["project_roots"] == ["package.json"]
    assert body["findings"][0]["rule_id"] == "RELATIVE_IMPORT_MISSING"
    assert body["findings"][0]["file_path"] == "src/main.ts"
    assert body["findings"][0]["line_number"] == 1


def test_scan_rejects_disallowed_path_without_exposing_allowed_root(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed_root = tmp_path / "authorized-secret-root"
    allowed_root.mkdir()
    outside_repository = tmp_path / "outside"
    outside_repository.mkdir()
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(allowed_root))

    response = client.post(
        "/api/scan", json={"repository_path": str(outside_repository)}
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Repository path is not authorized for scanning."}
    assert str(allowed_root) not in response.text


def test_scan_rejects_missing_path_without_echoing_it(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_path = tmp_path / "missing-private-path"
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(tmp_path))

    response = client.post("/api/scan", json={"repository_path": str(missing_path)})

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Repository path does not exist or is inaccessible."
    }
    assert str(missing_path) not in response.text


def test_scan_rejects_file_path_without_echoing_it(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = write_file(tmp_path, "not-a-directory.txt", "contents")
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(tmp_path))

    response = client.post("/api/scan", json={"repository_path": str(file_path)})

    assert response.status_code == 400
    assert response.json() == {"detail": "Repository path must be an existing directory."}
    assert str(file_path) not in response.text


def test_scan_rejects_repository_symlink(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    repository_link = tmp_path / "repository-link"
    repository_link.symlink_to(repository, target_is_directory=True)
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(tmp_path))

    response = client.post("/api/scan", json={"repository_path": str(repository_link)})

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid repository path."}
    assert str(repository_link) not in response.text


def test_malformed_scan_request_has_sanitized_error(client: TestClient) -> None:
    response = client.post("/api/scan", json={"repository_path": 7})

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid scan request."}
    assert '"input"' not in response.text


def test_missing_allowed_root_configuration_is_sanitized(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_configured_path = tmp_path / "not-to-disclose"
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(private_configured_path))

    response = client.post("/api/scan", json={"repository_path": str(tmp_path)})

    assert response.status_code == 500
    assert response.json() == {"detail": "Scanner authorization is not configured."}
    assert str(private_configured_path) not in response.text


def test_unsupported_platform_returns_safe_error(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_unsafe_platform(repository_path: str) -> dict[str, object]:
        raise ScannerSafetyError("private detail")

    monkeypatch.setattr(main, "scan_repository", raise_unsafe_platform)

    response = client.post("/api/scan", json={"repository_path": str(tmp_path)})

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Secure scanning is unavailable on this platform."
    }
    assert "private detail" not in response.text