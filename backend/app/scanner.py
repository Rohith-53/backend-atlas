"""Read-only repository discovery and heuristic JavaScript import scanning."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
}

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".cache",
    ".vite",
    ".turbo",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "vendor",
    "build",
    "dist",
    "out",
    "coverage",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "env",
}

SOURCE_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
}

RESOLUTION_EXTENSIONS = (
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".json",
)

SECRET_EXTENSIONS = {
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".p12",
    ".pfx",
    ".ppk",
    ".jks",
    ".keystore",
    ".secret",
    ".secrets",
}

SECRET_NAME_PARTS = {
    "credential",
    "credentials",
    "token",
    "tokens",
    "secret",
    "secrets",
    "privatekey",
    "private_key",
}
SECRET_CONFIG_NAMES = {".npmrc", ".pypirc", ".netrc"}


class ScannerConfigurationError(RuntimeError):
    """The allowed-root configuration is missing or invalid."""


class RepositoryNotAllowedError(PermissionError):
    """The selected repository is outside the configured roots."""


class ScannerSafetyError(RuntimeError):
    """The current platform cannot guarantee safe source-file reads."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int


def _allowed_roots(config: str | None = None) -> list[Path]:
    if config is None:
        config = os.environ.get("BACKEND_ATLAS_ALLOWED_ROOTS")
    if not config or not config.strip():
        raise ScannerConfigurationError(
            "BACKEND_ATLAS_ALLOWED_ROOTS must contain one or more existing directories"
        )

    configured_roots = config.split(os.pathsep)
    if any(not value.strip() for value in configured_roots):
        raise ScannerConfigurationError("BACKEND_ATLAS_ALLOWED_ROOTS contains an empty path")

    roots: list[Path] = []
    for value in configured_roots:
        try:
            root = Path(value).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ScannerConfigurationError(
                f"Configured allowed root is not accessible: {value}"
            ) from error
        if not root.is_dir():
            raise ScannerConfigurationError(f"Configured allowed root is not a directory: {value}")
        if root not in roots:
            roots.append(root)
    return roots


def _is_within(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _repository_path(value: str, roots: list[Path]) -> Path:
    if not value or not value.strip():
        raise ValueError("repository_path must not be empty")

    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise ValueError("repository_path must not be a symlink")
    try:
        repository = requested.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise FileNotFoundError(f"Repository path does not exist: {value}") from error
    if not repository.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {value}")
    if not _is_within(repository, roots):
        raise RepositoryNotAllowedError("Repository path is outside configured allowed roots")
    return repository


def _is_secret_file(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env") or name in SECRET_CONFIG_NAMES:
        return True
    if path.suffix.lower() in SECRET_EXTENSIONS:
        return True
    if name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "private_key"}:
        return True
    normalized_stem = re.sub(r"[^a-z0-9]", "", path.stem.lower())
    if normalized_stem in {"apikey", "apikeys"}:
        return True
    name_parts = {
        part.lower()
        for part in re.split(r"(?<=[a-z0-9])(?=[A-Z])|[._-]+", path.name)
        if part
    }
    return bool(name_parts & SECRET_NAME_PARTS)


def _walk_repository(repository: Path, roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for directory, directory_names, file_names in os.walk(repository, followlinks=False):
        current = Path(directory)
        directory_names[:] = [
            name
            for name in directory_names
            if name not in EXCLUDED_DIRECTORY_NAMES
            and not (current / name).is_symlink()
        ]
        for name in file_names:
            path = current / name
            if path.is_symlink() or _is_secret_file(path):
                continue
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if not resolved.is_file() or not _is_within(resolved, [repository]) or not _is_within(
                resolved, roots
            ):
                continue
            files.append(resolved)
    return sorted(files)


def _require_secure_open_support() -> None:
    if (
        os.name != "posix"
        or not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd
        or not Path("/proc/self/fd").is_dir()
    ):
        raise ScannerSafetyError(
            "Safe source reads require POSIX O_NOFOLLOW, dir_fd opens, and /proc/self/fd"
        )


def _opened_path(descriptor: int) -> Path:
    try:
        return Path(os.readlink(f"/proc/self/fd/{descriptor}")).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ScannerSafetyError("Could not validate an opened file descriptor") from error


def _read_source(path: Path, repository: Path) -> str | None:
    _require_secure_open_support()
    try:
        relative_path = path.relative_to(repository)
    except ValueError as error:
        raise ScannerSafetyError("Source file is outside the selected repository") from error
    if not relative_path.parts or any(part in {".", ".."} for part in relative_path.parts):
        raise ScannerSafetyError("Invalid source path")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    descriptors: list[int] = []
    try:
        root_descriptor = os.open(repository, directory_flags)
        descriptors.append(root_descriptor)
        if _opened_path(root_descriptor) != repository:
            raise ScannerSafetyError("Opened repository directory changed during scanning")

        parent_descriptor = root_descriptor
        for component in relative_path.parts[:-1]:
            parent_descriptor = os.open(
                component, directory_flags, dir_fd=parent_descriptor
            )
            descriptors.append(parent_descriptor)

        source_descriptor = os.open(
            relative_path.name, file_flags, dir_fd=parent_descriptor
        )
        descriptors.append(source_descriptor)
        if not stat.S_ISREG(os.fstat(source_descriptor).st_mode):
            return None
        if not _is_within(_opened_path(source_descriptor), [repository]):
            raise ScannerSafetyError("Opened source file is outside the selected repository")

        with os.fdopen(
            source_descriptor, "r", encoding="utf-8", errors="replace"
        ) as source:
            descriptors.remove(source_descriptor)
            return source.read()
    except OSError:
        return None
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(source)

    while index < length:
        character = source[index]
        if character.isspace():
            if character == "\n":
                line += 1
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end == -1:
                break
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end == -1:
                break
            line += source.count("\n", index, end + 2)
            index = end + 2
            continue
        if character in "'\"`":
            quote = character
            token_line = line
            index += 1
            value: list[str] = []
            while index < length:
                character = source[index]
                if character == "\\" and index + 1 < length:
                    escaped = source[index + 1]
                    if escaped == "\n":
                        line += 1
                    else:
                        value.append(escaped)
                    index += 2
                    continue
                if character == quote:
                    index += 1
                    break
                if character == "\n":
                    line += 1
                if quote != "`":
                    value.append(character)
                index += 1
            if quote != "`":
                tokens.append(Token("string", "".join(value), token_line))
            continue
        if character.isalpha() or character in "_$":
            start = index
            while index < length and (source[index].isalnum() or source[index] in "_$"):
                index += 1
            tokens.append(Token("identifier", source[start:index], line))
            continue
        tokens.append(Token("punctuation", character, line))
        index += 1
    return tokens


def _extract_imports(source: str) -> list[tuple[str, int]]:
    tokens = _tokenize(source)
    imports: list[tuple[str, int]] = []

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue

        if token.value == "require":
            if (
                index + 2 < len(tokens)
                and tokens[index + 1].value == "("
                and tokens[index + 2].kind == "string"
            ):
                imports.append((tokens[index + 2].value, token.line))
            continue

        if token.value not in {"import", "export"}:
            continue
        if index + 1 < len(tokens) and tokens[index + 1].kind == "string":
            imports.append((tokens[index + 1].value, token.line))
            continue
        if (
            token.value == "import"
            and index + 2 < len(tokens)
            and tokens[index + 1].value == "("
            and tokens[index + 2].kind == "string"
        ):
            imports.append((tokens[index + 2].value, token.line))
            continue

        stop = min(len(tokens), index + 200)
        for cursor in range(index + 1, stop - 1):
            current = tokens[cursor]
            if current.value == ";":
                break
            if cursor > index + 1 and current.kind == "identifier" and current.value in {
                "import",
                "export",
            }:
                break
            if (
                current.kind == "identifier"
                and current.value == "from"
                and tokens[cursor + 1].kind == "string"
            ):
                imports.append((tokens[cursor + 1].value, token.line))
                break
    return imports


def _resolve_import(specifier: str, source_file: Path, available: set[Path], is_typescript: bool) -> bool:
    relative_specifier = specifier.split("?", 1)[0].split("#", 1)[0]
    if not relative_specifier.startswith(("./", "../")):
        return True

    target = source_file.parent / relative_specifier
    candidates = [target]
    suffix = target.suffix.lower()
    if suffix:
        if is_typescript and suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            alternatives = {
                ".js": (".ts", ".tsx", ".d.ts"),
                ".jsx": (".tsx", ".d.ts"),
                ".mjs": (".mts",),
                ".cjs": (".cts",),
            }[suffix]
            candidates.extend(target.with_suffix(extension) for extension in alternatives)
    else:
        candidates.extend(Path(f"{target}{extension}") for extension in RESOLUTION_EXTENSIONS)
        candidates.extend(
            target / f"index{extension}" for extension in RESOLUTION_EXTENSIONS
        )
    return any(candidate in available for candidate in candidates)


def scan_repository(repository_path: str) -> dict[str, object]:
    """Scan an approved local repository without executing or modifying its files."""
    _require_secure_open_support()
    roots = _allowed_roots()
    repository = _repository_path(repository_path, roots)
    scanned_files = _walk_repository(repository, roots)
    available_files = set(scanned_files)

    manifests = sorted(
        path.relative_to(repository).as_posix()
        for path in scanned_files
        if path.name in MANIFEST_NAMES
    )
    is_typescript = any(
        path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}
        or path.name == "tsconfig.json"
        for path in scanned_files
    )

    findings: list[dict[str, object]] = []
    for source_file in scanned_files:
        if source_file.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        source = _read_source(source_file, repository)
        if source is None:
            continue
        relative_source = source_file.relative_to(repository).as_posix()
        for specifier, line_number in _extract_imports(source):
            if _resolve_import(specifier, source_file, available_files, is_typescript):
                continue
            lines = source.splitlines()
            evidence = lines[line_number - 1].strip() if line_number <= len(lines) else specifier
            evidence = evidence[:300]
            finding_key = f"{relative_source}:{line_number}:{specifier}"
            finding_id = hashlib.sha256(finding_key.encode("utf-8")).hexdigest()[:16]
            findings.append(
                {
                    "id": finding_id,
                    "severity": "warning",
                    "rule_id": "RELATIVE_IMPORT_MISSING",
                    "file_path": relative_source,
                    "line_number": line_number,
                    "evidence": evidence,
                    "explanation": (
                        f"Relative import {specifier!r} did not resolve to a scanned file. "
                        "This is a likely issue, not a confirmed runtime failure."
                    ),
                    "suggested_fix": (
                        "Update the import to a real relative target or add the missing file."
                    ),
                }
            )

    return {
        "repository_path": str(repository),
        "project_roots": manifests,
        "findings": findings,
    }