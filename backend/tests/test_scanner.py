from __future__ import annotations

import os
from pathlib import Path

import pytest

import app.scanner as scanner
from app.scanner import ScannerConfigurationError, ScannerSafetyError, scan_repository


def configure_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", str(root))


def write_file(root: Path, relative_path: str, content: str = "") -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_missing_repository_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure_root(monkeypatch, tmp_path)
    with pytest.raises(FileNotFoundError):
        scan_repository(str(tmp_path / "missing"))


def test_non_directory_repository_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure_root(monkeypatch, tmp_path)
    file_path = write_file(tmp_path, "not-a-directory.txt", "content")
    with pytest.raises(NotADirectoryError):
        scan_repository(str(file_path))


def test_missing_allowed_root_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BACKEND_ATLAS_ALLOWED_ROOTS", raising=False)
    with pytest.raises(ScannerConfigurationError):
        scan_repository(str(tmp_path))


@pytest.mark.parametrize("configured_value", ["", "/path/that/does/not/exist"])
def test_invalid_allowed_root_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured_value: str
) -> None:
    monkeypatch.setenv("BACKEND_ATLAS_ALLOWED_ROOTS", configured_value)
    with pytest.raises(ScannerConfigurationError):
        scan_repository(str(tmp_path))


def test_repository_symlink_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed_root = tmp_path / "allowed"
    repository = allowed_root / "repository"
    repository.mkdir(parents=True)
    link = allowed_root / "repository-link"
    link.symlink_to(repository, target_is_directory=True)
    configure_root(monkeypatch, allowed_root)

    with pytest.raises(ValueError, match="must not be a symlink"):
        scan_repository(str(link))


def test_symlink_escape_is_not_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed_root = tmp_path / "allowed"
    repository = allowed_root / "repository"
    external = tmp_path / "external"
    repository.mkdir(parents=True)
    external.mkdir()
    write_file(external, "package.json", "{}")
    write_file(external, "leak.js", "import './missing.js';")
    (repository / "external-link").symlink_to(external, target_is_directory=True)
    configure_root(monkeypatch, allowed_root)

    result = scan_repository(str(repository))
    assert result["project_roots"] == []
    assert result["findings"] == []


def test_discovers_common_project_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    for manifest in (
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    ):
        write_file(repository, manifest)

    result = scan_repository(str(repository))
    assert result["project_roots"] == [
        "Cargo.toml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
    ]


def test_excludes_exact_generated_directory_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    write_file(repository, "node_modules/package.json")
    write_file(repository, "not_node_modules/package.json")
    write_file(repository, "build/src.js", "import './missing.js';")
    write_file(repository, "my_build/src.js", "import './missing.js';")

    result = scan_repository(str(repository))
    assert result["project_roots"] == ["not_node_modules/package.json"]
    assert [finding["file_path"] for finding in result["findings"]] == ["my_build/src.js"]


def test_reports_missing_and_multiline_relative_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    source = """import {
  missingValue,
} from '../missing-module';
"""
    write_file(repository, "src/main.ts", source)

    findings = scan_repository(str(repository))["findings"]
    assert len(findings) == 1
    assert findings[0]["file_path"] == "src/main.ts"
    assert findings[0]["line_number"] == 1
    assert findings[0]["rule_id"] == "RELATIVE_IMPORT_MISSING"
    assert findings[0]["severity"] == "warning"
    assert findings[0]["evidence"] == "import {"


def test_explicit_js_import_resolves_to_typescript_alternative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    write_file(repository, "tsconfig.json", "{}")
    write_file(repository, "src/main.ts", 'import { value } from "./feature.js";')
    write_file(repository, "src/feature.tsx", "export const value = 1;")

    assert scan_repository(str(repository))["findings"] == []


def test_extensionless_and_index_ts_imports_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    write_file(repository, "src/main.ts", 'import "./widget";\nimport "./components";')
    write_file(repository, "src/widget.ts", "export {};")
    write_file(repository, "src/components/index.ts", "export {};")

    assert scan_repository(str(repository))["findings"] == []


def test_comments_and_string_contents_do_not_create_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    write_file(
        repository,
        "src/main.js",
        """// import './comment.js';
const text = "import('./quoted.js'); /* still quoted */";
/* require('./block-comment.js'); */
""",
    )

    assert scan_repository(str(repository))["findings"] == []


def test_secret_files_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    write_file(repository, ".env.production", "import './env-leak.js';")
    write_file(repository, ".envrc", "import './envrc-leak.js';")
    write_file(repository, ".npmrc", "import './npmrc-leak.js';")
    write_file(repository, "credentials.json", "import './credential-leak.js';")
    write_file(repository, "private.pem", "import './key-leak.js';")
    write_file(repository, "src/access_token.js", "import './token-leak.js';")
    write_file(repository, "src/authToken.js", "import './camel-token-leak.js';")

    assert scan_repository(str(repository))["findings"] == []


def test_api_key_filename_variants_are_skipped_but_regular_sources_are_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    for filename in ("api_key.ts", "apiKey.ts", "API-KEY.ts", "api.key.ts"):
        write_file(repository, f"src/{filename}", "import './secret-target.js';")
    write_file(
        repository,
        "src/client.ts",
        '// apiKey is read from config\nimport "./missing-client.js";',
    )

    findings = scan_repository(str(repository))["findings"]
    assert [finding["file_path"] for finding in findings] == ["src/client.ts"]


def test_replaced_source_symlink_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed_root = tmp_path / "allowed"
    repository = allowed_root / "repository"
    external = tmp_path / "outside.js"
    source_path = write_file(
        repository, "src/main.js", "export const original = true;"
    )
    write_file(external.parent, external.name, "import './escaped-missing.js';")
    configure_root(monkeypatch, allowed_root)

    original_open = scanner.os.open
    replaced = False

    def replace_before_open(path: str | bytes | os.PathLike[str], flags: int, *args: object, **kwargs: object) -> int:
        nonlocal replaced
        if path == source_path.name and kwargs.get("dir_fd") is not None and not replaced:
            parent_descriptor = kwargs["dir_fd"]
            scanner.os.unlink(path, dir_fd=parent_descriptor)
            scanner.os.symlink(external, path, dir_fd=parent_descriptor)
            replaced = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", replace_before_open)
    monkeypatch.setattr(
        scanner.os,
        "supports_dir_fd",
        scanner.os.supports_dir_fd | {replace_before_open},
    )

    result = scan_repository(str(repository))
    assert replaced
    assert result["findings"] == []


def test_unsupported_safe_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    configure_root(monkeypatch, tmp_path)
    monkeypatch.setattr(scanner.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ScannerSafetyError, match="Safe source reads require"):
        scan_repository(str(repository))


def test_repository_outside_allowed_root_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed_root = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed_root.mkdir()
    outside.mkdir()
    configure_root(monkeypatch, allowed_root)

    with pytest.raises(PermissionError):
        scan_repository(str(outside))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_symlinked_files_are_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed_root = tmp_path / "allowed"
    repository = allowed_root / "repository"
    outside = tmp_path / "outside.js"
    repository.mkdir(parents=True)
    write_file(tmp_path, "outside.js", "import './should-not-be-read.js';")
    (repository / "linked.js").symlink_to(outside)
    configure_root(monkeypatch, allowed_root)

    assert scan_repository(str(repository))["findings"] == []