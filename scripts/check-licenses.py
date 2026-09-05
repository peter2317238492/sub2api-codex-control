"""Validate repository licensing and third-party attribution metadata."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import tomllib

EXPECTED_COMPONENT_IDS = {
    "alembic",
    "codex",
    "coder-websocket",
    "crane",
    "go",
    "jsonschema",
    "lucide",
    "pinia",
    "psutil",
    "regexp2",
    "sub2api",
    "trivy",
    "vue",
    "x-text",
}
EXPECTED_MANIFEST_SHA256 = (
    "12bd737fc8713e2eb4e364dd3e7b64ee40de0fd6146a75712d28caccb7fb035b"
)
EXPECTED_THIRD_PARTY_NOTICES_SHA256 = (
    "c02c923418f0d68fd725f2760d4667b9f44804d027a87e42b61d677de146b380"
)
EXPECTED_GO_MODULE = "github.com/peter2317238492/sub2api-codex-control/connector"
EXPECTED_REPOSITORY = "https://github.com/peter2317238492/sub2api-codex-control"
OLD_GO_MODULE = "github.com/sub2api-codex/control/connector"
PACKAGE_JSON_PATHS = (
    Path("package.json"),
    Path("apps/pwa/package.json"),
    Path("packages/appserver-schema/package.json"),
    Path("packages/control-protocol/package.json"),
)
EXPECTED_WORKFLOW_SHA256 = {
    Path(".github/workflows/ci.yml"): (
        "2ed32cf28d1b5660f29ce051f38ca48df5fe7e893201270aefb8cf5ab51f3c23"
    ),
    Path(".github/workflows/connector-release.yml"): (
        "6272badd5a2452804a47210a841dad7f22f3f2a9d0d5117b2d8e4292e05fc6c1"
    ),
    Path(".github/workflows/control-images-release.yml"): (
        "4b765c511497d8455ed5fec7e4e6f50d0df40d8713d899dc9236629d1cac88e3"
    ),
}
# Formal release workflows may run only from their protected tag push, and
# their entry job must begin by proving the annotated tag sits on the current
# protected main head with an exact successful CI run.
PROTECTED_RELEASE_WORKFLOWS = {
    Path(".github/workflows/connector-release.yml"): ("connector-v*", "build"),
    Path(".github/workflows/control-images-release.yml"): ("control-v*", "validate"),
}
RELEASE_TAG_GUARD_STEP = (
    "Require the protected main commit and its exact successful CI run"
)
NOTICE_RELATIONSHIPS = {
    "codex": ("generated-material", "Generated protocol material"),
    "sub2api": ("compatibility-reference", "Compatibility contract"),
    "alembic": ("runtime-dependency", "Python runtime dependency"),
    "vue": ("runtime-dependency", "PWA runtime dependency"),
    "pinia": ("runtime-dependency", "PWA runtime dependency"),
    "lucide": ("runtime-dependency", "PWA icon dependency"),
    "go": ("build-runtime", "Connector build/runtime dependency"),
    "crane": ("release-build-tool", "Pinned OCI acquisition tool"),
    "trivy": ("security-build-tool", "Pinned vulnerability scanner"),
    "coder-websocket": ("runtime-dependency", "Connector dependency"),
    "jsonschema": ("runtime-dependency", "Connector dependency"),
    "regexp2": ("test-only-transitive", "Test-only transitive Connector dependency"),
    "x-text": ("transitive-runtime-dependency", "Transitive Connector dependency"),
    "psutil": ("operator-verification-tool", "Canary process verification"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path, errors: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        errors.append(f"cannot load JSON {path}: {error}")
        return None


def repo_file(root: Path, relative: str, errors: list[str]) -> Path | None:
    candidate = root / relative
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        errors.append(f"missing or unreadable file {relative}: {error}")
        return None
    if resolved != candidate.absolute():
        errors.append(f"license path must not traverse a symlink: {relative}")
        return None
    if resolved_root not in resolved.parents:
        errors.append(f"license path escapes repository: {relative}")
        return None
    if not resolved.is_file():
        errors.append(f"license path is not a regular file: {relative}")
        return None
    return resolved


def check_digest_file(
    root: Path,
    record: dict[str, Any],
    errors: list[str],
    *,
    allow_source_normalization: bool,
) -> None:
    relative = record.get("path")
    expected = record.get("file_sha256", record.get("sha256"))
    if not isinstance(relative, str) or not isinstance(expected, str):
        errors.append("license file record needs string path and SHA-256")
        return
    path = repo_file(root, relative, errors)
    if path is None:
        return
    content = path.read_bytes()
    actual = sha256_bytes(content)
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        errors.append(f"invalid recorded SHA-256 for {relative}")
    elif actual != expected:
        errors.append(
            f"SHA-256 mismatch for {relative}: expected {expected}, got {actual}"
        )

    if not allow_source_normalization:
        return
    source_sha = record.get("source_sha256")
    normalization = record.get("normalization")
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        errors.append(f"invalid source SHA-256 for {relative}")
        return
    if normalization == "none":
        normalized_source = content
    elif normalization == "append-final-newline":
        if not content.endswith(b"\n") or content.endswith(b"\n\n"):
            errors.append(f"{relative} must contain exactly one appended final newline")
            return
        normalized_source = content[:-1]
    elif normalization == "prepend-leading-newline-remove-final-newline":
        if not content.endswith(b"\n") or content.endswith(b"\n\n"):
            errors.append(f"{relative} must contain exactly one final newline")
            return
        normalized_source = b"\n" + content[:-1]
    else:
        errors.append(f"unsupported normalization for {relative}: {normalization!r}")
        return
    if sha256_bytes(normalized_source) != source_sha:
        errors.append(f"source-normalized SHA-256 mismatch for {relative}")


def check_version_evidence(
    root: Path, component: dict[str, Any], errors: list[str]
) -> None:
    component_id = component.get("id", "<unknown>")
    version = component.get("version")
    evidence = component.get("version_evidence")
    if not isinstance(version, str) or not isinstance(evidence, dict):
        errors.append(f"component {component_id} lacks version evidence")
        return
    relative = evidence.get("path")
    if not isinstance(relative, str):
        errors.append(f"component {component_id} has invalid evidence path")
        return
    path = repo_file(root, relative, errors)
    if path is None:
        return
    kind = evidence.get("kind")
    if kind == "exact-file":
        observed: Any = path.read_text(encoding="utf-8").strip()
    elif kind == "json-pointer":
        observed = load_json(path, errors)
        if observed is None:
            return
        for key in evidence.get("keys", []):
            if not isinstance(observed, dict) or key not in observed:
                errors.append(
                    f"component {component_id} evidence key is missing: {key!r}"
                )
                return
            observed = observed[key]
    elif kind == "python-constraint":
        package = re.escape(str(evidence.get("package", "")))
        match = re.search(
            rf"(?im)^{package}==([^\s#]+)\s*$", path.read_text(encoding="utf-8")
        )
        observed = match.group(1) if match else None
    elif kind == "pnpm-importer":
        package = str(evidence.get("package", ""))
        lock = path.read_text(encoding="utf-8")
        package_key = re.escape(f"'{package}'" if package.startswith("@") else package)
        match = re.search(
            rf"(?m)^\s{{6}}{package_key}:\n(?:\s{{8}}.*\n)*?\s{{8}}version: ([^\s(]+)",
            lock,
        )
        observed = match.group(1) if match else None
    elif kind == "go-toolchain-version":
        observed = load_json(path, errors)
        if observed is None:
            return
        for key in evidence.get("keys", []):
            if not isinstance(observed, dict) or key not in observed:
                errors.append(
                    f"component {component_id} evidence key is missing: {key!r}"
                )
                return
            observed = observed[key]
        match = re.fullmatch(r"go([0-9]+\.[0-9]+\.[0-9]+)", str(observed))
        observed = match.group(1) if match else None
    elif kind == "go-version":
        match = re.search(r"(?m)^go ([0-9.]+)$", path.read_text(encoding="utf-8"))
        observed = match.group(1) if match else None
    elif kind in {"go-require", "go-sum"}:
        module = re.escape(str(evidence.get("module", "")))
        match = re.search(
            rf"(?m)^[ \t]*(?:require[ \t]+)?{module} v([^\s/]+)(?:/go\.mod)?(?:\s|$)",
            path.read_text(encoding="utf-8"),
        )
        observed = match.group(1) if match else None
    else:
        errors.append(
            f"component {component_id} has unsupported evidence kind {kind!r}"
        )
        return
    if observed != version:
        errors.append(
            f"component {component_id} version evidence mismatch: expected {version}, got {observed!r}"
        )

    if component_id != "go":
        return
    baseline = component.get("language_baseline")
    expected_baseline = {
        "version": "1.25.0",
        "version_evidence": {
            "kind": "go-version",
            "path": "connector/go.mod",
        },
    }
    if baseline != expected_baseline:
        errors.append(
            "Go language baseline must remain explicitly bound to connector/go.mod"
        )
        return
    check_version_evidence(
        root,
        {
            "id": "go-language-baseline",
            "version": baseline["version"],
            "version_evidence": baseline["version_evidence"],
        },
        errors,
    )


def check_package_metadata(root: Path, errors: list[str]) -> None:
    expected_repo_url = f"git+{EXPECTED_REPOSITORY}.git"
    expected_homepage = f"{EXPECTED_REPOSITORY}#readme"
    expected_issues = f"{EXPECTED_REPOSITORY}/issues"
    for relative in PACKAGE_JSON_PATHS:
        data = load_json(root / relative, errors)
        if not isinstance(data, dict):
            continue
        if data.get("license") != "Apache-2.0":
            errors.append(f"{relative} must declare license Apache-2.0")
        if data.get("author") != "Sub2API Codex Control contributors":
            errors.append(f"{relative} must use the neutral contributors author")
        repository = data.get("repository")
        if (
            not isinstance(repository, dict)
            or repository.get("url") != expected_repo_url
        ):
            errors.append(f"{relative} has an unexpected repository URL")
        if data.get("homepage") != expected_homepage:
            errors.append(f"{relative} has an unexpected homepage")
        if data.get("bugs") != {"url": expected_issues}:
            errors.append(f"{relative} has an unexpected issue URL")

    pyproject_path = root / "apps/control-api/pyproject.toml"
    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        errors.append(f"cannot load {pyproject_path}: {error}")
        return
    project = pyproject.get("project", {})
    if project.get("license") != "Apache-2.0":
        errors.append("apps/control-api/pyproject.toml must declare Apache-2.0")
    if project.get("authors") != [{"name": "Sub2API Codex Control contributors"}]:
        errors.append(
            "apps/control-api/pyproject.toml must use the neutral contributors author"
        )
    urls = project.get("urls", {})
    if urls.get("Repository") != EXPECTED_REPOSITORY:
        errors.append(
            "apps/control-api/pyproject.toml has an unexpected repository URL"
        )
    if (
        urls.get("Homepage") != expected_homepage
        or urls.get("Issues") != expected_issues
    ):
        errors.append("apps/control-api/pyproject.toml has unexpected project URLs")


def check_go_module(root: Path, errors: list[str]) -> None:
    go_mod = (root / "connector/go.mod").read_text(encoding="utf-8")
    if not go_mod.startswith(f"module {EXPECTED_GO_MODULE}\n"):
        errors.append(f"connector/go.mod must use module {EXPECTED_GO_MODULE}")
    for path in (root / "connector").rglob("*.go"):
        text = path.read_text(encoding="utf-8")
        if OLD_GO_MODULE in text:
            errors.append(
                f"legacy private Go module import remains in {path.relative_to(root)}"
            )


def yaml_block(text: str, header: str, indent: int) -> str | None:
    """Return a simple YAML mapping block without accepting another peer key."""
    lines = text.splitlines()
    marker = f"{' ' * indent}{header}:"
    try:
        start = lines.index(marker)
    except ValueError:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            end = index
            break
    return "\n".join(lines[start + 1 : end])


def check_source_only_release_workflows(root: Path, errors: list[str]) -> None:
    workflows_root = root / ".github/workflows"
    try:
        actual_workflows = {path.relative_to(root) for path in workflows_root.iterdir()}
    except OSError as error:
        errors.append(f"cannot inspect workflow directory: {error}")
        return
    expected_workflows = set(EXPECTED_WORKFLOW_SHA256)
    if actual_workflows != expected_workflows:
        errors.append(
            "workflow file set mismatch: "
            f"expected {sorted(map(str, expected_workflows))}, "
            f"got {sorted(map(str, actual_workflows))}"
        )

    workflow_text: dict[Path, str] = {}
    for relative, expected_sha256 in EXPECTED_WORKFLOW_SHA256.items():
        try:
            checked_path = repo_file(root, relative.as_posix(), errors)
            if checked_path is None:
                continue
            workflow_bytes = checked_path.read_bytes()
            text = workflow_bytes.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"cannot read workflow {relative}: {error}")
            continue
        actual_sha256 = sha256_bytes(workflow_bytes)
        if actual_sha256 != expected_sha256:
            errors.append(
                f"{relative} SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
            )
        workflow_text[relative] = text

    for relative, (tag_pattern, entry_job) in PROTECTED_RELEASE_WORKFLOWS.items():
        text = workflow_text.get(relative)
        if text is None:
            continue

        trigger_block = yaml_block(text, "on", 0)
        trigger_lines = [
            line.strip()
            for line in (trigger_block or "").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if trigger_lines != ["push:", "tags:", f'- "{tag_pattern}"']:
            errors.append(
                f"{relative} must be triggered only by its protected {tag_pattern} tag push"
            )

        entry_block = yaml_block(text, entry_job, 2)
        if entry_block is None:
            errors.append(f"{relative} lacks protected release entry job {entry_job}")
        else:
            if RELEASE_TAG_GUARD_STEP not in entry_block:
                errors.append(
                    f"{relative} release entry job {entry_job} must first prove the "
                    "protected main commit and its exact successful CI run"
                )
            if re.search(r"(?m)^\s{4}if:", entry_block):
                errors.append(
                    f"{relative} release entry job {entry_job} must not be conditional"
                )


def check_third_party_notices(
    root: Path, components: list[Any], errors: list[str]
) -> None:
    path = root / "THIRD_PARTY_NOTICES.md"
    try:
        notices_bytes = path.read_bytes()
        notices = notices_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        errors.append(f"cannot read THIRD_PARTY_NOTICES.md: {error}")
        return
    actual_sha256 = sha256_bytes(notices_bytes)
    if actual_sha256 != EXPECTED_THIRD_PARTY_NOTICES_SHA256:
        errors.append(
            "THIRD_PARTY_NOTICES.md SHA-256 mismatch: "
            f"expected {EXPECTED_THIRD_PARTY_NOTICES_SHA256}, got {actual_sha256}"
        )

    header = "| Component | Version | Relationship | License |"
    separator = "| --- | --- | --- | --- |"
    lines = notices.splitlines()
    try:
        start = lines.index(header)
    except ValueError:
        errors.append("THIRD_PARTY_NOTICES.md lacks the canonical component table")
        rows: list[tuple[str, str, str, str]] = []
    else:
        if start + 1 >= len(lines) or lines[start + 1] != separator:
            errors.append(
                "THIRD_PARTY_NOTICES.md has an invalid component table separator"
            )
        rows = []
        for line in lines[start + 2 :]:
            if not line.startswith("|"):
                break
            cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
            if len(cells) != 4:
                errors.append(
                    f"THIRD_PARTY_NOTICES.md has an invalid component row: {line}"
                )
                continue
            rows.append(cells)

    expected_rows: list[tuple[str, str, str, str]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        component_id = component.get("id")
        relation = NOTICE_RELATIONSHIPS.get(component_id)
        if relation is None:
            errors.append(
                f"component {component_id!r} lacks a NOTICE relationship mapping"
            )
            continue
        manifest_relationship, notice_relationship = relation
        if component.get("relationship") != manifest_relationship:
            errors.append(
                f"component {component_id} relationship must be {manifest_relationship}"
            )
        license_expression = component.get("license_expression")
        expected_rows.append(
            (
                str(component.get("name")),
                str(component.get("version")),
                notice_relationship,
                str(license_expression).replace(" AND ", " and "),
            )
        )
    if rows != expected_rows:
        errors.append(
            "THIRD_PARTY_NOTICES.md component table does not match "
            "third_party/components.json names, versions, relationships, and licenses"
        )

    for required in (
        "This is an independent community project",
        "This initial public snapshot is source-only",
        "The `connector-v*` and `control-v*` tag release\nworkflows are disabled",
        "No prebuilt asset may be published before then",
    ):
        if required not in notices:
            errors.append(
                f"THIRD_PARTY_NOTICES.md lacks release policy text: {required}"
            )


def validate(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    manifest_path = root / "third_party/components.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        errors.append(f"cannot read {manifest_path}: {error}")
        return errors
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if manifest_sha256 != EXPECTED_MANIFEST_SHA256:
        errors.append(
            "third_party/components.json SHA-256 mismatch: "
            f"expected {EXPECTED_MANIFEST_SHA256}, got {manifest_sha256}"
        )
    manifest = load_json(manifest_path, errors)
    if not isinstance(manifest, dict):
        return errors
    if manifest.get("format_version") != 1:
        errors.append("third_party/components.json format_version must be 1")
    project = manifest.get("project")
    if (
        not isinstance(project, dict)
        or project.get("license_expression") != "Apache-2.0"
    ):
        errors.append("project license expression must be Apache-2.0")
    else:
        for key in ("license_file", "notice_file"):
            record = project.get(key)
            if isinstance(record, dict):
                check_digest_file(
                    root, record, errors, allow_source_normalization=False
                )
            else:
                errors.append(f"project {key} record is missing")

    components = manifest.get("components")
    if not isinstance(components, list):
        errors.append("third_party components must be an array")
        return errors
    ids = [
        component.get("id") for component in components if isinstance(component, dict)
    ]
    if len(ids) != len(set(ids)):
        errors.append("third_party component IDs must be unique")
    if set(ids) != EXPECTED_COMPONENT_IDS:
        errors.append(
            "third_party component set mismatch: "
            f"expected {sorted(EXPECTED_COMPONENT_IDS)}, got {sorted(str(value) for value in ids)}"
        )
    declared_license_paths: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            errors.append("third_party component entries must be objects")
            continue
        if not isinstance(component.get("license_expression"), str):
            errors.append(f"component {component.get('id')} lacks a license expression")
        check_version_evidence(root, component, errors)
        license_files = component.get("license_files")
        if not isinstance(license_files, list) or not license_files:
            errors.append(f"component {component.get('id')} lacks license files")
            continue
        for record in license_files:
            if isinstance(record, dict):
                relative = record.get("path")
                if isinstance(relative, str):
                    declared_license_paths.add(relative)
                check_digest_file(root, record, errors, allow_source_normalization=True)
            else:
                errors.append(
                    f"component {component.get('id')} has an invalid license record"
                )

    license_root = root / "third_party/licenses"
    actual_license_paths = {
        path.relative_to(root).as_posix()
        for path in license_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_license_paths != declared_license_paths:
        errors.append(
            "third_party license file set mismatch: "
            f"declared {sorted(declared_license_paths)}, actual {sorted(actual_license_paths)}"
        )

    sub2api = next(
        (
            component
            for component in components
            if isinstance(component, dict) and component.get("id") == "sub2api"
        ),
        None,
    )
    if (
        not isinstance(sub2api, dict)
        or sub2api.get("license_expression") != "LGPL-3.0-or-later"
    ):
        errors.append("Sub2API must be identified as LGPL-3.0-or-later")
    elif sub2api.get("license_declaration") != {
        "source_url": "https://raw.githubusercontent.com/Wei-Shaw/sub2api/e803e3851c0a7e222cfadeafad7b8636ab959d11/README.md",
        "source_sha256": "1c29e6c1e85681a8945ac1ade191e119b3c937e973f0ee367c0bed51be69ecf5",
        "text": "GNU Lesser General Public License v3.0 (or later)",
    }:
        errors.append("Sub2API or-later declaration evidence is missing or changed")

    check_package_metadata(root, errors)
    check_go_module(root, errors)
    check_source_only_release_workflows(root, errors)
    check_third_party_notices(root, components, errors)

    schema_readme = (root / "packages/appserver-schema/README.md").read_text(
        encoding="utf-8"
    )
    for required in (
        "https://github.com/openai/codex/tree/rust-v0.147.0",
        "third_party/licenses/Codex-LICENSE.txt",
        "third_party/licenses/Codex-NOTICE.txt",
        "not affiliated with, endorsed by, or sponsored by",
    ):
        if required not in schema_readme:
            errors.append(
                f"appserver schema README lacks required attribution: {required}"
            )

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"license-check: {error}", file=sys.stderr)
        return 1
    print("license-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
