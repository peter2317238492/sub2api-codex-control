from __future__ import annotations

import argparse
import ast
import copy
import functools
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
ADMISSION = REPO_ROOT / "deploy/scripts/image-rollout-admission.py"
ROLLOUT_RECORD_SCHEMA = REPO_ROOT / "deploy/schemas/image-rollout-record.schema.json"
CLOSURE_VERIFIER = REPO_ROOT / "deploy/scripts/record-authenticated-smoke-closure.py"
CLOSURE_SCHEMA = REPO_ROOT / "deploy/schemas/authenticated-smoke-closure.schema.json"
EXPECTED_SCHEMA_SHA256 = (
    "3d247f26e2faa54dbf2b9865bfdafa9e5f80bcf2a1a872a0401db0bf4add3e73"
)
# The frozen bootstrap artifact bundle is operator-private and is never
# published.  Point IMAGE_ROLLOUT_PRODUCT_ARTIFACT_ROOT at it to re-check the
# frozen constants against the real bundle; the check skips without it.
PRODUCT_ARTIFACT_ROOT = (
    Path(os.environ["IMAGE_ROLLOUT_PRODUCT_ARTIFACT_ROOT"]).resolve()
    if os.environ.get("IMAGE_ROLLOUT_PRODUCT_ARTIFACT_ROOT")
    else None
)
TEST_TEMP_ROOT = Path(tempfile.gettempdir()).resolve()
OLD_RELEASE = "0.1.0-bootstrap.old"
NEW_RELEASE = "0.1.0-bootstrap.new"
OLD_VCS = "1" * 64
SOURCE_MANIFEST_CONTENT = b"0444 24 fixture-source-record\n"
SOURCE_ARCHIVE_CONTENT = b"fixture source archive\n"
TRANSPORT_ARCHIVE_CONTENT = b"fixture transport archive\n"
NEW_VCS = hashlib.sha256(SOURCE_MANIFEST_CONTENT).hexdigest()
FIXTURE_BUNDLE_ID = "20260812T224530Z"
OLD_IMAGES = {
    "control-api": "sha256:" + "a" * 64,
    "pwa": "sha256:" + "b" * 64,
    "postgres-tools": "sha256:" + "c" * 64,
}
NEW_IMAGES = {
    "control-api": "sha256:" + "d" * 64,
    "pwa": "sha256:" + "e" * 64,
    "postgres-tools": "sha256:" + "f" * 64,
}
ARCHIVE_CONTENTS = {
    "control-api": b"control-api archive fixture\n",
    "pwa": b"pwa archive fixture\n",
    "postgres-tools": b"postgres tools archive fixture\n",
}
ARCHIVE_NAMES = {
    "control-api": "control-api-linux-amd64.tar",
    "pwa": "pwa-linux-amd64.tar",
    "postgres-tools": "postgres-tools-linux-amd64.tar",
}
SERVICE_COMPONENT = {
    "control-api": "control-api",
    "control-api-replica": "control-api",
    "control-migrate": "control-api",
    "codex-pwa": "pwa",
    "control-backup": "postgres-tools",
}
RUNNING_SERVICES = ("control-api", "control-api-replica", "codex-pwa")


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> bytes:
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def image_checksum_bytes() -> bytes:
    return b"".join(
        f"{sha256(ARCHIVE_CONTENTS[component])}  {filename}\n".encode("ascii")
        for component, filename in ARCHIVE_NAMES.items()
    )


def transport_checksum_bytes() -> bytes:
    entries = [
        (sha256(SOURCE_ARCHIVE_CONTENT), "source.tar.gz"),
        *[
            (sha256(ARCHIVE_CONTENTS[component]), filename)
            for component, filename in ARCHIVE_NAMES.items()
        ],
    ]
    return b"".join(
        f"{digest}  {filename}\n".encode("ascii") for digest, filename in entries
    )


def ready_record() -> dict[str, Any]:
    return {
        "artifact_directory": FIXTURE_BUNDLE_ID,
        "artifact_manifest_sha256": sha256(canonical_bytes(artifact_manifest())),
        "bundle_id": FIXTURE_BUNDLE_ID,
        "release": NEW_RELEASE,
        "schema_version": 1,
        "status": "ready",
        "transport": {
            "file": f"transport/production-bootstrap-{FIXTURE_BUNDLE_ID}.tar",
            "sha256": sha256(TRANSPORT_ARCHIVE_CONTENT),
        },
        "vcs_ref": NEW_VCS,
    }


def frozen_fixture_targets() -> dict[str, Any]:
    return {
        "TARGET_RELEASE": NEW_RELEASE,
        "TARGET_VCS_REF": NEW_VCS,
        "TARGET_MANIFEST_SHA256": sha256(canonical_bytes(artifact_manifest())),
        "TARGET_TRANSPORT_CHECKSUM_SHA256": sha256(transport_checksum_bytes()),
        "TARGET_READY_RECORD_SHA256": sha256(canonical_bytes(ready_record())),
        "TARGET_BUNDLE_ID": FIXTURE_BUNDLE_ID,
        "TARGET_TRANSPORT_SHA256": sha256(TRANSPORT_ARCHIVE_CONTENT),
        "TARGET_ARCHIVE_SHA256": {
            component: sha256(content)
            for component, content in ARCHIVE_CONTENTS.items()
        },
        "TARGET_IMAGE_IDS": NEW_IMAGES,
    }


def read_top_level_assignments(path: Path, names: set[str]) -> dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    module = ast.parse(source, filename=str(path))
    result: dict[str, Any] = {}
    for node in module.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        else:
            continue
        if isinstance(target, ast.Name) and target.id in names:
            result[target.id] = ast.literal_eval(node.value)
    if set(result) != names:
        raise AssertionError(
            f"frozen target set differs: {sorted(set(result) ^ names)}"
        )
    return result


def write_fixture_admission(
    output: Path, *, extra_replacements: dict[str, Any] | None = None
) -> None:
    replacements = frozen_fixture_targets()
    replacements.update(extra_replacements or {})
    source = ADMISSION.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    module = ast.parse(source, filename=str(ADMISSION))
    assignments: dict[str, tuple[int, int]] = {}
    for node in module.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        else:
            continue
        if isinstance(target, ast.Name) and target.id in replacements:
            if node.end_lineno is None or target.id in assignments:
                raise AssertionError(f"ambiguous frozen target: {target.id}")
            assignments[target.id] = (node.lineno - 1, node.end_lineno)
    if set(assignments) != set(replacements):
        raise AssertionError(
            f"frozen target assignment set differs: "
            f"{sorted(set(assignments) ^ set(replacements))}"
        )
    for name, (start, end) in sorted(
        assignments.items(), key=lambda item: item[1][0], reverse=True
    ):
        lines[start:end] = [f"{name} = {replacements[name]!r}\n"]
    output.write_text("".join(lines), encoding="utf-8")
    output.chmod(0o555)
    if read_top_level_assignments(output, set(replacements)) != replacements:
        raise AssertionError("temporary helper target rewrite did not round-trip")


def run_admission(
    *arguments: str,
    admission: Path = ADMISSION,
    input_data: bytes | None = None,
    expect_success: bool | None = True,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS"] = "1"
    result = subprocess.run(
        [sys.executable, "-I", str(admission), *arguments],
        check=False,
        capture_output=True,
        env=environment,
        input=input_data,
    )
    if expect_success is True and result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    if expect_success is False and result.returncode == 0:
        raise AssertionError(result.stdout.decode("utf-8", errors="replace"))
    return result


def jsonschema_python() -> Path | None:
    """Locate an interpreter that can import ``jsonschema``.

    The running interpreter is preferred so the external validation cross-check
    works anywhere the suite runs.  ``JSONSCHEMA_PYTHON`` overrides it.
    """
    candidates = [Path(sys.executable)]
    override = os.environ.get("JSONSCHEMA_PYTHON")
    if override:
        candidates.insert(0, Path(override))
    for path in candidates:
        if not path.exists():
            continue
        result = subprocess.run(
            [str(path), "-c", "import jsonschema"],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            return path
    return None


def compose_config(
    release: str, vcs_ref: str, images: dict[str, str]
) -> dict[str, Any]:
    services: dict[str, Any] = {}
    for name, component in SERVICE_COMPONENT.items():
        value: dict[str, Any] = {
            "image": images[component],
            "labels": {
                "com.sub2api-codex.component": name,
                "org.opencontainers.image.revision": vcs_ref,
                "org.opencontainers.image.version": release,
                "stable-label": "unchanged",
            },
            "read_only": True,
            "restart": "unless-stopped",
        }
        if name in {"control-api", "control-api-replica", "control-migrate"}:
            value["environment"] = {
                "CONTROL_BUILD_VCS_REF": vcs_ref,
                "CONTROL_BUILD_VERSION": release,
                "STABLE_ENVIRONMENT": "unchanged",
            }
        if name in {"control-api", "control-api-replica"}:
            published = "18090" if name == "control-api" else "18093"
            value["ports"] = [
                {
                    "host_ip": "127.0.0.1",
                    "mode": "ingress",
                    "protocol": "tcp",
                    "published": published,
                    "target": 8090,
                }
            ]
            value["networks"] = {"sub2api-network": {}}
        elif name == "codex-pwa":
            value["ports"] = [
                {
                    "host_ip": "127.0.0.1",
                    "mode": "ingress",
                    "protocol": "tcp",
                    "published": "18091",
                    "target": 8080,
                }
            ]
            value["networks"] = {"pwa-network": {}}
        else:
            value["networks"] = {"sub2api-network": {}}
        services[name] = value
    return {
        "name": "sub2api-codex-control",
        "networks": {
            "pwa-network": {"name": "sub2api-codex-control_pwa-network"},
            "sub2api-network": {"external": True, "name": "sub2api-network"},
        },
        "services": services,
        "volumes": {"stable-volume": {"name": "stable-volume"}},
    }


def artifact_manifest() -> dict[str, Any]:
    return {
        "artifact_kind": "unsigned-production-bootstrap-images",
        "format_version": 5,
        "images": {
            component: {
                "archive": ARCHIVE_NAMES[component],
                "archive_sha256": sha256(ARCHIVE_CONTENTS[component]),
                "archive_size": len(ARCHIVE_CONTENTS[component]),
                "daemon_image_id": image_id,
                "oci_labels": {
                    "org.opencontainers.image.revision": NEW_VCS,
                    "org.opencontainers.image.source": "sub2api-codex-control",
                    "org.opencontainers.image.version": NEW_RELEASE,
                },
                "tag": f"example/{component}:new",
            }
            for component, image_id in NEW_IMAGES.items()
        },
        "release": NEW_RELEASE,
        "schema_version": 1,
        "source": {
            "canonical_hash_manifest": {
                "file": "source-files.manifest",
                "is_vcs_ref": True,
                "sha256": NEW_VCS,
            }
        },
        "status": "ready",
        "transport": {
            "checksum_file": "transport-SHA256SUMS",
            "checksum_file_sha256": sha256(transport_checksum_bytes()),
            "image_checksum_file": "bootstrap-images.sha256",
            "image_checksum_file_sha256": sha256(image_checksum_bytes()),
        },
        "trust_mode": "unsigned-first-deployment-v1",
        "vcs_ref": NEW_VCS,
    }


class TemporaryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_TEMP_ROOT)
        self.root = Path(self.temporary.name)
        self.tools_root = self.root / "rollout-tools"
        scripts = self.tools_root / "deploy/scripts"
        schemas = self.tools_root / "deploy/schemas"
        scripts.mkdir(parents=True)
        schemas.mkdir(parents=True)
        self.admission = scripts / "image-rollout-admission.py"
        write_fixture_admission(self.admission)
        self.schema_path = schemas / "image-rollout-record.schema.json"
        shutil.copyfile(ROLLOUT_RECORD_SCHEMA, self.schema_path)
        self.schema_path.chmod(0o444)
        self.smoke_helper = scripts / "image-rollout-smoke.py"
        self.smoke_helper.write_bytes(b"#!/usr/bin/env python3\n")
        self.smoke_helper.chmod(0o555)
        self.wrapper = scripts / "rollout-bootstrap-images.sh"
        self.wrapper.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.wrapper.chmod(0o555)
        self.tools_manifest, self.tools_admission = self.write_tools_evidence()
        for directory in (scripts, schemas, scripts.parent, self.tools_root):
            directory.chmod(0o555)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def path(self, name: str, value: Any) -> Path:
        path = self.root / name
        write_json(path, value)
        return path

    def write_tools_evidence(self) -> tuple[Path, Path]:
        members = {
            "deploy/scripts/image-rollout-admission.py": (self.admission, "0555"),
            "deploy/scripts/image-rollout-smoke.py": (self.smoke_helper, "0555"),
            "deploy/scripts/rollout-bootstrap-images.sh": (self.wrapper, "0555"),
            "deploy/schemas/image-rollout-record.schema.json": (
                self.schema_path,
                "0444",
            ),
        }
        files = {
            relative: {
                "mode": mode,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for relative, (path, mode) in members.items()
        }
        manifest_value = {
            "files": files,
            "identity_sha256": sha256(canonical_bytes(files)[:-1]),
            "schema_version": 1,
            "type": "image-rollout-tools-manifest-v1",
        }
        manifest = self.tools_root / "rollout-tools.manifest.json"
        manifest_raw = write_json(manifest, manifest_value)
        manifest.chmod(0o444)
        verifier_sha = "8" * 64
        admission_value = {
            "archive": {
                "basename": "image-rollout-tools.tar",
                "sha256": "7" * 64,
                "size": 10240,
            },
            "command": "extract",
            "external_verifier": {
                "basename": "build-image-rollout-tools.py",
                "sha256": verifier_sha,
                "size": 4096,
            },
            "manifest": {
                "basename": manifest.name,
                "sha256": sha256(manifest_raw),
                "size": len(manifest_raw),
            },
            "members": {
                relative: {
                    "basename": path.name,
                    "mode": mode,
                    "sha256": files[relative]["sha256"],
                    "size": files[relative]["size"],
                }
                for relative, (path, mode) in members.items()
            },
            "schema_version": 1,
            "self_sha256": verifier_sha,
            "status": "extracted",
            "tooling_identity": manifest_value["identity_sha256"],
            "type": "image-rollout-tools-admission-v1",
        }
        admission = self.tools_root / "rollout-tools.admission.json"
        write_json(admission, admission_value)
        admission.chmod(0o444)
        return manifest, admission

    def run_admission(
        self,
        *arguments: str,
        input_data: bytes | None = None,
        expect_success: bool | None = True,
    ) -> subprocess.CompletedProcess[bytes]:
        return run_admission(
            *arguments,
            admission=self.admission,
            input_data=input_data,
            expect_success=expect_success,
        )

    def project_inspections(
        self,
        inspections: Any,
        *,
        expect_success: bool = True,
    ) -> tuple[dict[str, Any] | None, subprocess.CompletedProcess[bytes] | None]:
        if not isinstance(inspections, list) or len(inspections) != len(
            RUNNING_SERVICES
        ):
            raise AssertionError("inspection fixture must contain exactly three items")
        containers: dict[str, Any] = {}
        for service, inspection in zip(RUNNING_SERVICES, inspections):
            result = self.run_admission(
                "project-container",
                "--service",
                service,
                input_data=canonical_bytes([inspection]),
                expect_success=None,
            )
            if result.returncode != 0:
                if expect_success:
                    raise AssertionError(
                        result.stderr.decode("utf-8", errors="replace")
                    )
                return None, result
            projected = json.loads(result.stdout)
            self.assertEqual(projected["service"], service)
            self.assertEqual(projected["schema_version"], 1)
            containers[service] = projected["projection"]
        projection = {"containers": containers, "schema_version": 1}
        self.assertNotIn(
            "PRIVATE_SENTINEL", canonical_bytes(projection).decode("ascii")
        )
        return projection, None


class PlanTests(TemporaryCase):
    def setUp(self) -> None:
        super().setUp()
        self.old = compose_config(OLD_RELEASE, OLD_VCS, OLD_IMAGES)
        self.new = compose_config(NEW_RELEASE, NEW_VCS, NEW_IMAGES)
        self.artifact = artifact_manifest()

    def invoke(
        self,
        *,
        old: Any | None = None,
        new: Any | None = None,
        artifact: Any | None = None,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        old_path = self.path("old.json", self.old if old is None else old)
        new_path = self.path("new.json", self.new if new is None else new)
        artifact_path = self.path(
            "artifact.json", self.artifact if artifact is None else artifact
        )
        return self.run_admission(
            "plan",
            "--old-compose",
            str(old_path),
            "--new-compose",
            str(new_path),
            "--artifact-manifest",
            str(artifact_path),
            expect_success=expect_success,
        )

    def test_exact_allowlist_is_admitted_and_output_is_canonical(self) -> None:
        result = self.invoke()
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, canonical_bytes(value))
        self.assertEqual(value["status"], "admitted")
        self.assertEqual(value["old"]["images"], OLD_IMAGES)
        self.assertEqual(value["new"]["images"], NEW_IMAGES)
        self.assertEqual(value["new_compose"], self.new)
        self.assertEqual(
            value["allowed_changes"],
            {
                "environment": ["CONTROL_BUILD_VCS_REF", "CONTROL_BUILD_VERSION"],
                "labels": [
                    "org.opencontainers.image.revision",
                    "org.opencontainers.image.version",
                ],
                "service_fields": ["image"],
                "services": list(SERVICE_COMPONENT),
            },
        )

    def test_each_image_field_is_bound_to_the_artifact(self) -> None:
        for name in SERVICE_COMPONENT:
            with self.subTest(name=name):
                new = copy.deepcopy(self.new)
                new["services"][name]["image"] = OLD_IMAGES[SERVICE_COMPONENT[name]]
                self.invoke(new=new, expect_success=False)

    def test_each_environment_identity_field_is_required(self) -> None:
        for name in ("control-api", "control-api-replica", "control-migrate"):
            for key in ("CONTROL_BUILD_VERSION", "CONTROL_BUILD_VCS_REF"):
                with self.subTest(name=name, key=key):
                    new = copy.deepcopy(self.new)
                    new["services"][name]["environment"][key] = "bad"
                    self.invoke(new=new, expect_success=False)

    def test_each_label_identity_field_is_required(self) -> None:
        for name in SERVICE_COMPONENT:
            for key in (
                "org.opencontainers.image.version",
                "org.opencontainers.image.revision",
            ):
                with self.subTest(name=name, key=key):
                    new = copy.deepcopy(self.new)
                    new["services"][name]["labels"][key] = "bad"
                    self.invoke(new=new, expect_success=False)

    def test_changes_outside_allowlist_fail_closed(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "top level": lambda value: value.update(name="different-project"),
            "stable service field": lambda value: value["services"][
                "control-api"
            ].update(read_only=False),
            "stable environment": lambda value: value["services"]["control-api"][
                "environment"
            ].update(STABLE_ENVIRONMENT="changed"),
            "stable label": lambda value: value["services"]["codex-pwa"][
                "labels"
            ].update(**{"stable-label": "changed"}),
            "network": lambda value: value["services"]["codex-pwa"].update(
                networks={"sub2api-network": {}}
            ),
            "port": lambda value: value["services"]["control-api"]["ports"][0].update(
                published="18092"
            ),
            "missing service": lambda value: value["services"].pop("control-migrate"),
            "extra service": lambda value: value["services"].update(extra={}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                new = copy.deepcopy(self.new)
                mutate(new)
                self.invoke(new=new, expect_success=False)

    def test_artifact_release_vcs_and_image_bindings_fail_closed(self) -> None:
        mutations: list[Callable[[dict[str, Any]], None]] = [
            lambda value: value.update(release=OLD_RELEASE),
            lambda value: value.update(vcs_ref=OLD_VCS),
            lambda value: value["source"]["canonical_hash_manifest"].update(
                sha256=OLD_VCS
            ),
            lambda value: value["images"]["pwa"].update(
                daemon_image_id=OLD_IMAGES["pwa"]
            ),
            lambda value: value["images"]["control-api"]["oci_labels"].update(
                **{"org.opencontainers.image.version": OLD_RELEASE}
            ),
            lambda value: value["images"].update(extra={}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                artifact = copy.deepcopy(self.artifact)
                mutate(artifact)
                self.invoke(artifact=artifact, expect_success=False)

    def test_duplicate_json_key_is_rejected(self) -> None:
        old = self.root / "old.json"
        old.write_text('{"services":{},"services":{}}\n', encoding="utf-8")
        old.chmod(0o600)
        result = self.run_admission(
            "plan",
            "--old-compose",
            str(old),
            "--new-compose",
            str(self.path("new.json", self.new)),
            "--artifact-manifest",
            str(self.path("artifact.json", self.artifact)),
            expect_success=False,
        )
        self.assertIn(b"duplicate object key", result.stderr)

    def test_symlink_hardlink_and_relative_inputs_are_rejected(self) -> None:
        target = self.path("target.json", self.old)
        symlink = self.root / "symlink.json"
        symlink.symlink_to(target)
        hardlink = self.root / "hardlink.json"
        os.link(target, hardlink)
        new = self.path("new.json", self.new)
        artifact = self.path("artifact.json", self.artifact)
        for path in (symlink, target):
            with self.subTest(path=path.name):
                self.run_admission(
                    "plan",
                    "--old-compose",
                    str(path),
                    "--new-compose",
                    str(new),
                    "--artifact-manifest",
                    str(artifact),
                    expect_success=False,
                )
        relative = os.path.relpath(hardlink, Path.cwd())
        self.run_admission(
            "plan",
            "--old-compose",
            relative,
            "--new-compose",
            str(new),
            "--artifact-manifest",
            str(artifact),
            expect_success=False,
        )


def create_migrations(root: Path) -> None:
    versions = root / "migrations" / "versions"
    versions.mkdir(parents=True)
    parent: str | None = None
    for index in range(1, 9):
        revision = f"20260101_{index:04d}"
        raw = (
            "from __future__ import annotations\n\n"
            f"revision: str = {revision!r}\n"
            f"down_revision: str | None = {parent!r}\n"
        ).encode()
        path = versions / f"{revision}_step_{index}.py"
        path.write_bytes(raw)
        path.chmod(0o600)
        parent = revision


def normalize_source_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


@functools.lru_cache(maxsize=1)
def closure_fixture_python() -> Path:
    candidates = (
        Path(sys.executable),
        Path("/private/tmp/sub2api-closure-v2/bin/python"),
        Path("/opt/homebrew/bin/python3"),
    )
    for candidate in dict.fromkeys(candidates):
        if not candidate.exists():
            continue
        probe = subprocess.run(
            [
                str(candidate),
                "-I",
                "-c",
                "import sys; from datetime import UTC; assert sys.version_info >= (3, 11)",
            ],
            check=False,
            capture_output=True,
        )
        if probe.returncode == 0:
            return candidate
    raise unittest.SkipTest("Python 3.11+ closure fixture producer is unavailable")


def run_closure_verifier(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [str(closure_fixture_python()), "-I", str(CLOSURE_VERIFIER), *arguments],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result


class BaselineTests(TemporaryCase):
    def setUp(self) -> None:
        super().setUp()
        self.bundle_dir = self.root / FIXTURE_BUNDLE_ID
        self.bundle_dir.mkdir(mode=0o700)
        self.artifact = artifact_manifest()
        write_json(self.bundle_dir / "artifact-manifest.json", self.artifact)
        for component, filename in ARCHIVE_NAMES.items():
            archive_path = self.bundle_dir / filename
            archive_path.write_bytes(ARCHIVE_CONTENTS[component])
            archive_path.chmod(0o600)
        checksum_path = self.bundle_dir / "bootstrap-images.sha256"
        checksum_path.write_bytes(image_checksum_bytes())
        checksum_path.chmod(0o600)
        transport_checksum_path = self.bundle_dir / "transport-SHA256SUMS"
        transport_checksum_path.write_bytes(transport_checksum_bytes())
        transport_checksum_path.chmod(0o600)
        source_archive_path = self.bundle_dir / "source.tar.gz"
        source_archive_path.write_bytes(SOURCE_ARCHIVE_CONTENT)
        source_archive_path.chmod(0o600)
        source_manifest_path = self.bundle_dir / "source-files.manifest"
        source_manifest_path.write_bytes(SOURCE_MANIFEST_CONTENT)
        source_manifest_path.chmod(0o600)
        self.ready_path = (
            self.bundle_dir.parent
            / f"production-bootstrap-{FIXTURE_BUNDLE_ID}.READY.json"
        )
        write_json(self.ready_path, ready_record())
        self.deployment_id = "c536c183-26e4-4e8e-9e66-db57e7053501"
        self.deployment = self.root / f"bootstrap-20260812T134654Z-{self.deployment_id}"
        self.deployment.mkdir(mode=0o700)
        self.plan = self.make_plan()
        self.old_plan = {
            "api_image": OLD_IMAGES["control-api"],
            "backup_image": OLD_IMAGES["postgres-tools"],
            "format_version": 1,
            "public_origin": "https://control.example.com",
            "pwa_image": OLD_IMAGES["pwa"],
            "release": OLD_RELEASE,
            "source_revision": OLD_VCS,
            "status": "admitted",
        }
        self.old_images = {
            "api": {
                "image_id": OLD_IMAGES["control-api"],
                "source": "sub2api-codex-control",
            },
            "backup": {
                "image_id": OLD_IMAGES["postgres-tools"],
                "source": "sub2api-codex-control",
            },
            "format_version": 1,
            "pwa": {
                "image_id": OLD_IMAGES["pwa"],
                "source": "sub2api-codex-control",
            },
            "release": OLD_RELEASE,
            "source_revision": OLD_VCS,
            "status": "admitted",
        }
        self.old_running = {
            "containers": {
                name: {
                    "container_id": str(index) * 64,
                    "health": "healthy",
                    "image_id": OLD_IMAGES[SERVICE_COMPONENT[name]],
                    "network": (
                        "sub2api-codex-control_pwa-network"
                        if name == "codex-pwa"
                        else "sub2api-network"
                    ),
                    "published_port": {
                        "control-api": "18090",
                        "control-api-replica": "18093",
                        "codex-pwa": "18091",
                    }[name],
                }
                for index, name in enumerate(RUNNING_SERVICES, 3)
            },
            "format_version": 1,
            "pwa_network": {"name": "sub2api-codex-control_pwa-network"},
            "status": "admitted",
        }
        self.old_compose = compose_config(OLD_RELEASE, OLD_VCS, OLD_IMAGES)
        self.old_compose_raw = write_json(
            self.deployment / "compose-config.json", self.old_compose
        )
        self.old_plan["compose_sha256"] = sha256(self.old_compose_raw)
        self.old_plan_raw = write_json(self.deployment / "plan.json", self.old_plan)
        self.old_images_raw = write_json(
            self.deployment / "images.json", self.old_images
        )
        self.old_running_raw = write_json(
            self.deployment / "running-containers.json", self.old_running
        )
        original_smoke = self.deployment / "production-smoke.txt"
        original_smoke.write_bytes(b"fixture pre-closure smoke evidence\n")
        original_smoke.chmod(0o600)
        verified_evidence = {
            "compose_plan": {
                "path": str(self.deployment / "plan.json"),
                "sha256": sha256(self.old_plan_raw),
                "size": len(self.old_plan_raw),
            },
            "local_images": {
                "path": str(self.deployment / "images.json"),
                "sha256": sha256(self.old_images_raw),
                "size": len(self.old_images_raw),
            },
            "running_containers": {
                "path": str(self.deployment / "running-containers.json"),
                "sha256": sha256(self.old_running_raw),
                "size": len(self.old_running_raw),
            },
            "production_smoke": {
                "path": str(original_smoke),
                "sha256": sha256_file(original_smoke),
                "size": original_smoke.stat().st_size,
            },
        }
        admission = {
            "admission_binding_sha256": "7" * 64,
            "admission_mode": "fresh-backup-v1",
            "fresh": True,
            "manifest_sha256": "8" * 64,
            "snapshot_directory": "/secure/backups/image-rollout-fixture",
            "stale_exception": None,
        }
        self.bootstrap = {
            "authenticated_smoke_pending": True,
            "bootstrap_exceptions": {
                "stale_production_backup": False,
                "sub2api_public_connect": False,
                "unauthenticated_smoke": True,
            },
            "format_version": 1,
            "normal_signed_deployment_required_for_next_release": True,
            "production_backup_admissions": {
                "after_bootstrap": dict(admission),
                "before_migration": dict(admission),
                "initial": dict(admission),
            },
            "recorded_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "signed_release_verified": False,
            "status": "bootstrapped-unsigned",
            "trust_mode": "unsigned-first-deployment-v1",
            "verified_evidence": verified_evidence,
        }
        self.bootstrap_raw = canonical_bytes(self.bootstrap)
        bootstrap_path = self.deployment / "bootstrap-deployment.json"
        write_json(bootstrap_path, self.bootstrap)
        run_closure_verifier(
            "--bootstrap-record", str(bootstrap_path), "--prepare-challenge"
        )
        challenge_path = self.deployment / "authenticated-smoke-challenge.json"
        challenge_raw = challenge_path.read_bytes()
        challenge = json.loads(challenge_raw)
        descriptions = read_top_level_assignments(
            CLOSURE_VERIFIER, {"EXPECTED_CHECK_DESCRIPTIONS"}
        )["EXPECTED_CHECK_DESCRIPTIONS"]
        smoke_raw = (
            "\n".join(
                [
                    *(
                        f"ok {index} - {description}"
                        for index, description in enumerate(descriptions, 1)
                    ),
                    (
                        "1..84 # closure-challenge-sha256="
                        f"{sha256(challenge_raw)} target-binding-sha256="
                        f"{challenge['target']['binding_sha256']}"
                    ),
                ]
            )
            + "\n"
        ).encode("utf-8")
        producer_smoke = self.root / "authenticated-smoke-producer.log"
        producer_smoke.write_bytes(smoke_raw)
        producer_smoke.chmod(0o600)
        run_closure_verifier(
            "--bootstrap-record",
            str(bootstrap_path),
            "--smoke-log",
            str(producer_smoke),
        )
        self.closure = json.loads(
            (self.deployment / "authenticated-smoke-closure.json").read_bytes()
        )
        self.source = {
            "admission": True,
            "bundle_file_count": 36,
            "bundle_id": FIXTURE_BUNDLE_ID,
            "kind": "source",
            "release": NEW_RELEASE,
            "schema_version": 1,
            "source_file_count": 1426,
            "source_root_verified": True,
            "status": "verified",
            "vcs_ref": NEW_VCS,
        }
        self.bundle = copy.deepcopy(self.source)
        self.bundle["kind"] = "bundle"
        self.archive = copy.deepcopy(self.source)
        self.archive.update(
            admission=False,
            kind="archive",
            source_root_verified=False,
            status="archive-verified-non-admission",
        )
        self.old_source = self.root / "old-source"
        self.new_source = self.root / "new-source"
        create_migrations(self.old_source)
        shutil.copytree(self.old_source / "migrations", self.new_source / "migrations")
        source_scripts = self.new_source / "deploy/scripts"
        source_schemas = self.new_source / "deploy/schemas"
        source_scripts.mkdir(parents=True)
        source_schemas.mkdir(parents=True)
        shutil.copyfile(
            CLOSURE_VERIFIER,
            source_scripts / "record-authenticated-smoke-closure.py",
        )
        shutil.copyfile(
            CLOSURE_SCHEMA,
            source_schemas / "authenticated-smoke-closure.schema.json",
        )
        normalize_source_tree(self.new_source)
        (source_scripts / "record-authenticated-smoke-closure.py").chmod(0o555)
        self.migration_state = {
            "current_revision": "20260101_0008",
            "head_revision": "20260101_0008",
        }
        self.operator = {
            "acknowledged_at": "2026-08-13T00:00:00Z",
            "allowed_operations": [
                "codex-pwa-rollout",
                "control-api-replica-rollout",
                "control-api-rollout",
                "image-load",
                "image-only-compose-plan",
                "production-smoke",
                "rollback",
                "runtime-verification",
            ],
            "duplicate_backup_prohibited": True,
            "forbidden_operations": ["backup", "database-migration"],
            "reason": "operator-prohibited-duplicate-backup",
            "schema_version": 1,
            "scope": "bootstrap-image-only-followup-v1",
            "type": "no-duplicate-backup-operator-instruction-v1",
        }
        self.current_before = self.make_current_before()

    def make_plan(self) -> dict[str, Any]:
        old_path = self.path(
            "compose-old-source.json",
            compose_config(OLD_RELEASE, OLD_VCS, OLD_IMAGES),
        )
        new_path = self.path(
            "compose-new-source.json",
            compose_config(NEW_RELEASE, NEW_VCS, NEW_IMAGES),
        )
        artifact_path = self.path("artifact-source.json", self.artifact)
        result = self.run_admission(
            "plan",
            "--old-compose",
            str(old_path),
            "--new-compose",
            str(new_path),
            "--artifact-manifest",
            str(artifact_path),
        )
        return json.loads(result.stdout)

    def make_current_before(self) -> dict[str, Any]:
        compose = self.plan["new_compose"]
        result: list[dict[str, Any]] = []
        for name in RUNNING_SERVICES:
            historical = self.old_running["containers"][name]
            service = compose["services"][name]
            port = service["ports"][0]
            target = f"{port['target']}/tcp"
            ports = {target: [{"HostIp": "127.0.0.1", "HostPort": port["published"]}]}
            network_key = next(iter(service["networks"]))
            network = compose["networks"][network_key]["name"]
            result.append(
                {
                    "Config": {
                        "Env": ["PRIVATE_SENTINEL=must-not-survive-projection"],
                        "Labels": {
                            "com.docker.compose.project": compose["name"],
                            "com.docker.compose.service": name,
                            "org.opencontainers.image.revision": OLD_VCS,
                            "org.opencontainers.image.version": OLD_RELEASE,
                        },
                    },
                    "HostConfig": {"PortBindings": ports},
                    "Id": historical["container_id"],
                    "Image": historical["image_id"],
                    "NetworkSettings": {
                        "Networks": {network: {}},
                        "Ports": ports,
                    },
                    "RestartCount": 0,
                    "State": {
                        "Health": {"Status": "healthy"},
                        "Running": True,
                        "Status": "running",
                    },
                }
            )
        projection, failure = self.project_inspections(result)
        if failure is not None or projection is None:
            raise AssertionError("valid current-before fixture was not projected")
        return projection

    def invoke(
        self,
        *,
        plan: Any | None = None,
        old_plan: Any | None = None,
        old_images: Any | None = None,
        old_running: Any | None = None,
        bootstrap: Any | None = None,
        closure: Any | None = None,
        source: Any | None = None,
        bundle: Any | None = None,
        archive: Any | None = None,
        current_before: Any | None = None,
        migration_state: Any | None = None,
        operator: Any | None = None,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        paths = {
            "plan": self.path("plan.json", self.plan if plan is None else plan),
            "old-plan": self.path(
                str(self.deployment / "plan.json"),
                self.old_plan if old_plan is None else old_plan,
            ),
            "old-images": self.path(
                str(self.deployment / "images.json"),
                self.old_images if old_images is None else old_images,
            ),
            "old-running": self.path(
                str(self.deployment / "running-containers.json"),
                self.old_running if old_running is None else old_running,
            ),
            "old-compose": self.deployment / "compose-config.json",
            "current-before-inspect": self.path(
                "current-before.json",
                self.current_before if current_before is None else current_before,
            ),
            "bootstrap-record": self.deployment / "bootstrap-deployment.json",
            "closure-record": self.deployment / "authenticated-smoke-closure.json",
            "source-evidence": self.path(
                "source-evidence.json", self.source if source is None else source
            ),
            "bundle-evidence": self.path(
                "bundle-evidence.json", self.bundle if bundle is None else bundle
            ),
            "archive-evidence": self.path(
                "archive-evidence.json", self.archive if archive is None else archive
            ),
            "artifact-manifest": self.bundle_dir / "artifact-manifest.json",
            "ready-record": self.ready_path,
            "migration-state": self.path(
                "migration-state.json",
                self.migration_state if migration_state is None else migration_state,
            ),
            "operator-exception": self.path(
                "operator-exception.json",
                self.operator if operator is None else operator,
            ),
        }
        write_json(
            paths["bootstrap-record"],
            self.bootstrap if bootstrap is None else bootstrap,
        )
        write_json(
            paths["closure-record"], self.closure if closure is None else closure
        )
        arguments = ["baseline"]
        for name, path in paths.items():
            arguments.extend((f"--{name}", str(path)))
        arguments.extend(("--old-source-root", str(self.old_source)))
        arguments.extend(("--new-source-root", str(self.new_source)))
        arguments.extend(("--bundle-dir", str(self.bundle_dir)))
        arguments.extend(("--tools-manifest", str(self.tools_manifest)))
        arguments.extend(("--tools-admission", str(self.tools_admission)))
        return self.run_admission(*arguments, expect_success=expect_success)

    def test_closed_byte_identical_baseline_is_admitted(self) -> None:
        result = self.invoke()
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, canonical_bytes(value))
        self.assertTrue(value["no_backup"])
        self.assertTrue(value["no_migration"])
        self.assertEqual(value["migrations"]["count"], 8)
        self.assertEqual(value["migrations"]["head"], "20260101_0008")
        self.assertEqual(value["old_admission"]["images"], OLD_IMAGES)
        self.assertEqual(
            value["bootstrap_deployment"]["deployment_id"], self.deployment_id
        )
        self.assertEqual(
            value["operator_exception_sha256"],
            sha256(canonical_bytes(self.operator)),
        )

    def test_old_admission_image_and_running_bindings_fail_closed(self) -> None:
        images = copy.deepcopy(self.old_images)
        images["api"]["image_id"] = NEW_IMAGES["control-api"]
        self.invoke(old_images=images, expect_success=False)
        running = copy.deepcopy(self.old_running)
        running["containers"]["control-api"]["health"] = "unhealthy"
        self.invoke(old_running=running, expect_success=False)

    def test_bootstrap_closure_hash_and_smoke_fail_closed(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["bootstrap_record"]["sha256"] = "0" * 64
        self.invoke(closure=closure, expect_success=False)
        closure = copy.deepcopy(self.closure)
        closure["authenticated_smoke"]["checks_passed"] = 83
        self.invoke(closure=closure, expect_success=False)

    def test_source_and_bundle_bindings_fail_closed(self) -> None:
        source = copy.deepcopy(self.source)
        source["vcs_ref"] = OLD_VCS
        self.invoke(source=source, expect_success=False)
        bundle = copy.deepcopy(self.bundle)
        bundle["release"] = OLD_RELEASE
        self.invoke(bundle=bundle, expect_success=False)

    def test_operator_instruction_fields_fail_closed(self) -> None:
        mutations: list[Callable[[dict[str, Any]], None]] = [
            lambda value: value.update(
                type="no-duplicate-backup-operator-instruction-v2"
            ),
            lambda value: value.update(reason="wrong"),
            lambda value: value.update(scope="wrong"),
            lambda value: value.update(duplicate_backup_prohibited=False),
            lambda value: value.update(forbidden_operations=["backup"]),
            lambda value: value.update(allowed_operations=["image-load"]),
            lambda value: value.update(acknowledged_at="2026-08-13T00:00:00+00:00"),
            lambda value: value.update(extra=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                operator = copy.deepcopy(self.operator)
                mutate(operator)
                self.invoke(operator=operator, expect_success=False)

    def test_operator_instruction_duplicate_json_hardlink_and_missing_fail_closed(
        self,
    ) -> None:
        paths = {
            "plan": self.path("operator-plan.json", self.plan),
            "old-plan": self.path("operator-old-plan.json", self.old_plan),
            "old-images": self.path("operator-old-images.json", self.old_images),
            "old-running": self.path("operator-old-running.json", self.old_running),
            "old-compose": self.deployment / "compose-config.json",
            "current-before-inspect": self.path(
                "operator-current-before.json", self.current_before
            ),
            "artifact-manifest": self.bundle_dir / "artifact-manifest.json",
            "ready-record": self.ready_path,
            "source-evidence": self.path("operator-source.json", self.source),
            "bundle-evidence": self.path("operator-bundle.json", self.bundle),
            "archive-evidence": self.path("operator-archive.json", self.archive),
            "migration-state": self.path(
                "operator-migration-state.json", self.migration_state
            ),
        }
        bootstrap = self.deployment / "bootstrap-deployment.json"
        closure = self.deployment / "authenticated-smoke-closure.json"
        write_json(bootstrap, self.bootstrap)
        write_json(closure, self.closure)

        def arguments(operator: Path) -> list[str]:
            result = ["baseline"]
            for name, path in paths.items():
                result.extend((f"--{name}", str(path)))
            result.extend(("--bootstrap-record", str(bootstrap)))
            result.extend(("--closure-record", str(closure)))
            result.extend(("--old-source-root", str(self.old_source)))
            result.extend(("--new-source-root", str(self.new_source)))
            result.extend(("--bundle-dir", str(self.bundle_dir)))
            result.extend(("--operator-exception", str(operator)))
            result.extend(("--tools-manifest", str(self.tools_manifest)))
            result.extend(("--tools-admission", str(self.tools_admission)))
            return result

        missing = self.root / "missing-operator.json"
        self.run_admission(*arguments(missing), expect_success=False)
        duplicate = self.root / "duplicate-operator.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        duplicate.chmod(0o600)
        result = self.run_admission(*arguments(duplicate), expect_success=False)
        self.assertIn(b"duplicate object key", result.stderr)
        target = self.path("operator-hardlink-target.json", self.operator)
        alias = self.root / "operator-hardlink.json"
        os.link(target, alias)
        self.run_admission(*arguments(alias), expect_success=False)

    def test_migration_byte_drift_count_and_current_head_fail_closed(self) -> None:
        changed = self.new_source / "migrations/versions/20260101_0004_step_4.py"
        original = changed.read_bytes()
        changed.chmod(0o600)
        changed.write_bytes(original + b"# changed\n")
        self.invoke(expect_success=False)
        changed.write_bytes(original)
        changed.chmod(0o444)
        versions = self.new_source / "migrations/versions"
        versions.chmod(0o755)
        ninth = self.new_source / "migrations/versions/20260101_0009_step_9.py"
        ninth.write_text(
            "revision = '20260101_0009'\ndown_revision = '20260101_0008'\n",
            encoding="utf-8",
        )
        self.invoke(expect_success=False)
        ninth.unlink()
        versions.chmod(0o555)
        state = copy.deepcopy(self.migration_state)
        state["current_revision"] = "20260101_0007"
        self.invoke(migration_state=state, expect_success=False)


def container_inspections(plan: dict[str, Any]) -> list[dict[str, Any]]:
    compose = plan["new_compose"]
    identities = plan["new"]
    result: list[dict[str, Any]] = []
    for index, name in enumerate(RUNNING_SERVICES, 6):
        service = compose["services"][name]
        port = service["ports"][0]
        target = f"{port['target']}/tcp"
        published = port["published"]
        network_key = next(iter(service["networks"]))
        network = compose["networks"][network_key]["name"]
        ports = {target: [{"HostIp": "127.0.0.1", "HostPort": published}]}
        result.append(
            {
                "Config": {
                    "Env": ["PRIVATE_SENTINEL=must-not-survive-projection"],
                    "Labels": {
                        "com.docker.compose.project": compose["name"],
                        "com.docker.compose.service": name,
                        "org.opencontainers.image.revision": identities["vcs_ref"],
                        "org.opencontainers.image.version": identities["release"],
                    },
                },
                "HostConfig": {"PortBindings": ports},
                "Id": str(index) * 64,
                "Image": identities["images"][SERVICE_COMPONENT[name]],
                "NetworkSettings": {"Networks": {network: {}}, "Ports": ports},
                "RestartCount": 0,
                "State": {
                    "Health": {"Status": "healthy"},
                    "Running": True,
                    "Status": "running",
                },
            }
        )
    return result


class RunningTests(TemporaryCase):
    def setUp(self) -> None:
        super().setUp()
        old = self.path(
            "old-compose.json", compose_config(OLD_RELEASE, OLD_VCS, OLD_IMAGES)
        )
        new = self.path(
            "new-compose.json", compose_config(NEW_RELEASE, NEW_VCS, NEW_IMAGES)
        )
        artifact = self.path("artifact.json", artifact_manifest())
        output = self.run_admission(
            "plan",
            "--old-compose",
            str(old),
            "--new-compose",
            str(new),
            "--artifact-manifest",
            str(artifact),
        )
        self.plan = json.loads(output.stdout)
        self.inspections = container_inspections(self.plan)

    def invoke(
        self,
        inspections: Any | None = None,
        *,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        projection, projection_failure = self.project_inspections(
            self.inspections if inspections is None else inspections,
            expect_success=expect_success,
        )
        if projection_failure is not None:
            return projection_failure
        if projection is None:
            raise AssertionError("container projection produced no result")
        return self.run_admission(
            "running",
            "--plan",
            str(self.path("plan.json", self.plan)),
            "--inspect",
            str(
                self.path(
                    "inspect.json",
                    projection,
                )
            ),
            expect_success=expect_success,
        )

    def test_exact_running_projection_is_admitted(self) -> None:
        result = self.invoke()
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, canonical_bytes(value))
        self.assertEqual(set(value["containers"]), set(RUNNING_SERVICES))
        self.assertTrue(
            all(item["health"] == "healthy" for item in value["containers"].values())
        )

    def test_image_health_port_network_and_service_fail_closed(self) -> None:
        def locate(value: list[dict[str, Any]], name: str) -> dict[str, Any]:
            return next(
                item
                for item in value
                if item["Config"]["Labels"]["com.docker.compose.service"] == name
            )

        mutations: list[Callable[[list[dict[str, Any]]], None]] = [
            lambda value: locate(value, "control-api").update(
                Image=OLD_IMAGES["control-api"]
            ),
            lambda value: locate(value, "codex-pwa")["State"]["Health"].update(
                Status="unhealthy"
            ),
            lambda value: locate(value, "control-api-replica")["HostConfig"].update(
                PortBindings={}
            ),
            lambda value: locate(value, "codex-pwa")["NetworkSettings"].update(
                Networks={"wrong": {}}
            ),
            lambda value: locate(value, "control-api")["Config"]["Labels"].update(
                **{"com.docker.compose.service": "control-migrate"}
            ),
            lambda value: locate(value, "control-api")["Config"]["Labels"].update(
                **{"org.opencontainers.image.version": OLD_RELEASE}
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                inspections = copy.deepcopy(self.inspections)
                mutate(inspections)
                if index == 2:
                    locate(inspections, "control-api-replica")[
                        "NetworkSettings"
                    ].update(Ports={})
                self.invoke(inspections, expect_success=False)


class FrozenProductTargetTests(unittest.TestCase):
    def test_product_target_constants_match_immutable_artifact_and_ready(self) -> None:
        if PRODUCT_ARTIFACT_ROOT is None:
            self.skipTest(
                "set IMAGE_ROLLOUT_PRODUCT_ARTIFACT_ROOT to the operator-private "
                "bootstrap artifact bundle to re-check the frozen constants"
            )
        bundle_id = "20260812T224530Z"
        bundle = PRODUCT_ARTIFACT_ROOT / bundle_id
        manifest_path = bundle / "artifact-manifest.json"
        ready_path = (
            PRODUCT_ARTIFACT_ROOT / f"production-bootstrap-{bundle_id}.READY.json"
        )
        manifest = json.loads(manifest_path.read_bytes())
        ready = json.loads(ready_path.read_bytes())
        targets = read_top_level_assignments(ADMISSION, set(frozen_fixture_targets()))

        expected = {
            "TARGET_RELEASE": manifest["release"],
            "TARGET_VCS_REF": manifest["vcs_ref"],
            "TARGET_MANIFEST_SHA256": sha256_file(manifest_path),
            "TARGET_TRANSPORT_CHECKSUM_SHA256": sha256_file(
                bundle / "transport-SHA256SUMS"
            ),
            "TARGET_READY_RECORD_SHA256": sha256_file(ready_path),
            "TARGET_BUNDLE_ID": ready["bundle_id"],
            "TARGET_TRANSPORT_SHA256": sha256_file(
                PRODUCT_ARTIFACT_ROOT / ready["transport"]["file"]
            ),
            "TARGET_ARCHIVE_SHA256": {
                component: sha256_file(bundle / image["archive"])
                for component, image in manifest["images"].items()
            },
            "TARGET_IMAGE_IDS": {
                component: image["daemon_image_id"]
                for component, image in manifest["images"].items()
            },
        }
        self.assertEqual(targets, expected)
        self.assertEqual(ready["artifact_directory"], bundle_id)
        self.assertEqual(
            ready["artifact_manifest_sha256"], expected["TARGET_MANIFEST_SHA256"]
        )
        self.assertEqual(
            manifest["transport"]["checksum_file_sha256"],
            expected["TARGET_TRANSPORT_CHECKSUM_SHA256"],
        )
        self.assertEqual(
            ready["transport"]["sha256"], expected["TARGET_TRANSPORT_SHA256"]
        )


def failed_record_context(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = {
        key: None
        for key in (
            "archive_evidence",
            "artifact_manifest",
            "bootstrap_record",
            "bundle_dir",
            "bundle_evidence",
            "closure_record",
            "current_before_inspect",
            "new_compose",
            "old_compose",
            "operator_exception",
            "source_evidence",
            "source_root",
            "ready_record",
            "smoke_challenge",
            "tools_admission",
            "tools_manifest",
        )
    }
    context = {
        "completed_at": "2026-08-13T00:00:01Z",
        "created_at": "2026-08-13T00:00:00Z",
        "failure_stage": "post-load-pre-rollout",
        "operations": {
            "archives_loaded": True,
            "backup_invoked": False,
            "build_invoked": False,
            "down_invoked": False,
            "load_invoked": True,
            "migrate_invoked": False,
            "postgres_tools_executed": False,
            "pull_invoked": False,
            "python_dont_write_bytecode": True,
        },
        "paths": paths,
        "rollback": {
            "completed_at": "2026-08-13T00:00:01Z",
            "evidence": None,
            "invariants_restored": True,
            "started_at": "2026-08-13T00:00:00Z",
            "status": "not-required",
            "steps": [],
            "trigger_stage": "post-load-pre-rollout",
        },
        "rollout_id": "07e976a6-7519-41cb-ac8a-f37d860cc7de",
        "schema_version": 1,
        "status": "failed",
        "steps": [
            {
                "after_inspect": None,
                "completed_at": None,
                "order": order,
                "readiness_evidence": None,
                "recreated": False,
                "service": service,
                "started_at": None,
                "status": "not-run",
            }
            for order, service in enumerate(
                ("control-api-replica", "control-api", "codex-pwa"), 1
            )
        ],
        "type": "bootstrap-image-rollout-context-v1",
    }
    smoke = {
        "check_catalog_sha256": None,
        "check_count": 0,
        "checks_passed": 0,
        "challenge_sha256": None,
        "completed_at": None,
        "result_sha256": None,
        "schema_version": "image-rollout-smoke-result-v1",
        "started_at": None,
        "status": "not-run",
        "target_binding_sha256": None,
    }
    return context, smoke


class RecordSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = BaselineTests(
            methodName="test_closed_byte_identical_baseline_is_admitted"
        )
        self.fixture.setUp()
        self.root = self.fixture.root
        self.admission = self.fixture.admission
        baseline_result = self.fixture.invoke()
        self.baseline_path = self.fixture.path(
            "baseline-admission.json", json.loads(baseline_result.stdout)
        )
        self.plan_path = self.root / "plan.json"
        self.context, smoke = failed_record_context(self.root)
        self.context["paths"].update(
            {
                "archive_evidence": str(self.root / "archive-evidence.json"),
                "artifact_manifest": str(
                    self.fixture.bundle_dir / "artifact-manifest.json"
                ),
                "bootstrap_record": str(
                    self.fixture.deployment / "bootstrap-deployment.json"
                ),
                "bundle_dir": str(self.fixture.bundle_dir),
                "bundle_evidence": str(self.root / "bundle-evidence.json"),
                "closure_record": str(
                    self.fixture.deployment / "authenticated-smoke-closure.json"
                ),
                "current_before_inspect": str(self.root / "current-before.json"),
                "new_compose": str(self.root / "compose-new-source.json"),
                "old_compose": str(self.fixture.deployment / "compose-config.json"),
                "operator_exception": str(self.root / "operator-exception.json"),
                "source_evidence": str(self.root / "source-evidence.json"),
                "source_root": str(self.fixture.new_source),
                "ready_record": str(self.fixture.ready_path),
                "tools_admission": str(self.fixture.tools_admission),
                "tools_manifest": str(self.fixture.tools_manifest),
            }
        )
        self.context_path = self.fixture.path("record-context.json", self.context)
        self.smoke = smoke
        self.schema = json.loads(ROLLOUT_RECORD_SCHEMA.read_bytes())
        self.schema_path = self.fixture.schema_path
        self.record_path = self.root / "image-rollout-record.json"
        produced = self.fixture.run_admission(
            "record",
            "--context",
            str(self.context_path),
            "--plan",
            str(self.plan_path),
            "--baseline",
            str(self.baseline_path),
            "--schema",
            str(self.schema_path),
            "--output",
            str(self.record_path),
        )
        self.record = json.loads(produced.stdout)
        self.assertEqual(self.record_path.read_bytes(), produced.stdout)

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def run_record(
        self,
        context: dict[str, Any],
        *,
        label: str,
        include_plan: bool = True,
        include_baseline: bool = True,
        expect_success: bool = True,
    ) -> tuple[subprocess.CompletedProcess[bytes], Path]:
        context_path = self.fixture.path(f"{label}-context.json", context)
        output_directory = self.root / label
        output_directory.mkdir(mode=0o700)
        output = output_directory / "image-rollout-record.json"
        arguments = ["record", "--context", str(context_path)]
        if include_plan:
            arguments.extend(("--plan", str(self.plan_path)))
        if include_baseline:
            arguments.extend(("--baseline", str(self.baseline_path)))
        arguments.extend(("--schema", str(self.schema_path), "--output", str(output)))
        result = self.fixture.run_admission(*arguments, expect_success=expect_success)
        if expect_success:
            self.assertEqual(output.read_bytes(), result.stdout)
        else:
            self.assertFalse(output.exists())
        return result, output

    def validate(
        self,
        *,
        record: Any | None = None,
        schema: Any | None = None,
        expect_success: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        admission = self.admission
        schema_path = self.schema_path
        record_value = copy.deepcopy(self.record if record is None else record)
        if schema is not None:
            schema_root = self.root / f"schema-fixture-{os.urandom(4).hex()}"
            scripts = schema_root / "deploy/scripts"
            schemas = schema_root / "deploy/schemas"
            scripts.mkdir(parents=True)
            schemas.mkdir(parents=True)
            schema_path = schemas / "image-rollout-record.schema.json"
            schema_raw = write_json(schema_path, schema)
            schema_path.chmod(0o444)
            admission = scripts / "image-rollout-admission.py"
            write_fixture_admission(
                admission,
                extra_replacements={"TARGET_SCHEMA_SHA256": sha256(schema_raw)},
            )
            record_value["tooling"]["record_schema"]["sha256"] = sha256(schema_raw)
            record_value["tooling"]["record_schema"]["size"] = len(schema_raw)
            tooling_members = {
                "deploy/scripts/image-rollout-admission.py": {
                    "mode": "0555",
                    "sha256": record_value["tooling"]["admission_helper"]["sha256"],
                    "size": record_value["tooling"]["admission_helper"]["size"],
                },
                "deploy/scripts/image-rollout-smoke.py": {
                    "mode": "0555",
                    "sha256": record_value["tooling"]["smoke_helper"]["sha256"],
                    "size": record_value["tooling"]["smoke_helper"]["size"],
                },
                "deploy/scripts/rollout-bootstrap-images.sh": {
                    "mode": "0555",
                    "sha256": record_value["tooling"]["wrapper"]["sha256"],
                    "size": record_value["tooling"]["wrapper"]["size"],
                },
                "deploy/schemas/image-rollout-record.schema.json": {
                    "mode": "0444",
                    "sha256": sha256(schema_raw),
                    "size": len(schema_raw),
                },
            }
            record_value["tooling"]["tooling_identity"] = sha256(
                canonical_bytes(tooling_members)[:-1]
            )
            for directory in (scripts, schemas, scripts.parent, schema_root):
                directory.chmod(0o555)
        return run_admission(
            "validate-record",
            "--record",
            str(
                self.fixture.path(
                    f"record-{os.urandom(4).hex()}.json",
                    record_value,
                )
            ),
            "--schema",
            str(schema_path),
            admission=admission,
            expect_success=expect_success,
        )

    def test_helper_generated_record_passes_closed_and_external_validation(
        self,
    ) -> None:
        result = self.validate(expect_success=True)
        self.assertEqual(json.loads(result.stdout)["status"], "valid")
        runtime = jsonschema_python()
        if runtime is None:
            self.skipTest("jsonschema runtime is unavailable")
        external = subprocess.run(
            [
                str(runtime),
                "-c",
                (
                    "import json,sys; "
                    "from jsonschema import Draft202012Validator,FormatChecker; "
                    "s=json.load(open(sys.argv[1])); v=json.load(open(sys.argv[2])); "
                    "Draft202012Validator.check_schema(s); "
                    "Draft202012Validator(s,format_checker=FormatChecker()).validate(v)"
                ),
                str(self.schema_path),
                str(self.record_path),
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(
            external.returncode,
            0,
            external.stderr.decode("utf-8", errors="replace"),
        )

    def test_plan_only_failure_preserves_fixed_tooling_evidence(self) -> None:
        context = copy.deepcopy(self.context)
        context["failure_stage"] = "baseline"
        context["operations"].update(archives_loaded=False, load_invoked=False)
        context["rollback"]["trigger_stage"] = "baseline"
        context["paths"] = {
            key: (value if key in {"tools_admission", "tools_manifest"} else None)
            for key, value in context["paths"].items()
        }
        result, _ = self.run_record(
            context,
            label="plan-only",
            include_baseline=False,
        )
        record = json.loads(result.stdout)
        self.assertIsNotNone(record["tooling"])
        self.assertIsNotNone(record["evidence"]["plan"])
        self.assertIsNone(record["evidence"]["baseline"])
        for key in (
            "base_bootstrap",
            "bundle",
            "compose",
            "images",
            "operator_exception",
            "source",
        ):
            self.assertIsNone(record[key])

    def test_pre_load_failure_record_preserves_verified_baseline(self) -> None:
        context = copy.deepcopy(self.context)
        context["failure_stage"] = "image-load"
        context["operations"].update(archives_loaded=False, load_invoked=False)
        context["rollback"]["trigger_stage"] = "image-load"
        result, _ = self.run_record(context, label="pre-load-failure")
        record = json.loads(result.stdout)
        self.assertIsNotNone(record["tooling"])
        self.assertIsNotNone(record["evidence"]["baseline"])
        self.assertFalse(record["bundle"]["archives_loaded"])
        self.assertFalse(record["compose"]["load_invoked"])
        self.assertEqual(
            [step["status"] for step in record["steps"]],
            ["not-run", "not-run", "not-run"],
        )
        self.assertEqual(record["rollback"]["status"], "not-required")

    def test_failed_rollback_keeps_complete_reverse_forward_list(self) -> None:
        context = copy.deepcopy(self.context)
        context["completed_at"] = "2026-08-13T00:00:07Z"
        context["failure_stage"] = "post-rollout-pre-smoke"
        new_projection, projection_failure = self.fixture.project_inspections(
            container_inspections(self.fixture.plan)
        )
        self.assertIsNone(projection_failure)
        self.assertIsNotNone(new_projection)
        new_inspect = self.fixture.path("forward-new-containers.json", new_projection)
        old_inspect = self.fixture.path(
            "rollback-old-containers.json", self.fixture.current_before
        )
        for index, step in enumerate(context["steps"], 1):
            readiness = self.fixture.path(
                f"forward-{index}-readiness.json", {"status": "ready"}
            )
            step.update(
                after_inspect=str(new_inspect),
                completed_at=f"2026-08-13T00:00:0{index + 1}Z",
                readiness_evidence=str(readiness),
                recreated=True,
                started_at=f"2026-08-13T00:00:0{index}Z",
                status="succeeded",
            )
        rollback_evidence = self.fixture.path(
            "rollback-summary.json", {"status": "failed"}
        )
        rollback_steps = []
        for index, service in enumerate(
            ("codex-pwa", "control-api", "control-api-replica"), 1
        ):
            failed = index == 1
            step_evidence = None
            if not failed:
                step_evidence = str(
                    self.fixture.path(
                        f"rollback-{index}-readiness.json",
                        {"status": "ready"},
                    )
                )
            rollback_steps.append(
                {
                    "completed_at": f"2026-08-13T00:00:0{index + 4}Z",
                    "evidence": step_evidence,
                    "inspect": None if failed else str(old_inspect),
                    "order": index,
                    "service": service,
                    "started_at": f"2026-08-13T00:00:0{index + 3}Z",
                    "status": "failed" if failed else "succeeded",
                }
            )
        context["rollback"] = {
            "completed_at": "2026-08-13T00:00:07Z",
            "evidence": str(rollback_evidence),
            "invariants_restored": False,
            "started_at": "2026-08-13T00:00:04Z",
            "status": "failed",
            "steps": rollback_steps,
            "trigger_stage": context["failure_stage"],
        }
        result, _ = self.run_record(context, label="failed-full-rollback")
        record = json.loads(result.stdout)
        self.assertEqual(record["rollback"]["status"], "failed")
        self.assertEqual(
            [step["service"] for step in record["rollback"]["steps"]],
            ["codex-pwa", "control-api", "control-api-replica"],
        )
        truncated = copy.deepcopy(context)
        truncated["rollback"]["steps"].pop()
        rejected, _ = self.run_record(
            truncated,
            label="failed-truncated-rollback",
            expect_success=False,
        )
        self.assertIn(b"complete exact reverse forward prefix", rejected.stderr)

    def test_record_publication_retries_short_writes(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "fixture_image_rollout_admission", self.admission
        )
        if spec is None or spec.loader is None:
            self.fail("temporary admission helper could not be imported")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output_directory = self.root / "short-write"
        output_directory.mkdir(mode=0o700)
        output = output_directory / "image-rollout-record.json"
        arguments = argparse.Namespace(
            baseline=self.baseline_path,
            context=self.context_path,
            invariants=None,
            output=output,
            plan=self.plan_path,
            running=None,
            schema=self.schema_path,
            smoke=None,
            resume_existing=False,
        )
        requested_lengths: list[int] = []
        original_write = module.os.write
        original_test_override = os.environ.get(
            "IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS"
        )

        def short_write(descriptor: int, value: bytes) -> int:
            requested_lengths.append(len(value))
            return original_write(descriptor, value[:23])

        module.os.write = short_write
        os.environ["IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS"] = "1"
        try:
            record = module.record(arguments)
        finally:
            module.os.write = original_write
            if original_test_override is None:
                os.environ.pop("IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS", None)
            else:
                os.environ["IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS"] = (
                    original_test_override
                )
        self.assertGreater(len(requested_lengths), 1)
        self.assertGreater(requested_lengths[0], 23)
        self.assertEqual(output.read_bytes(), canonical_bytes(record))

    def test_unresolved_local_reference_fails_closed(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["properties"]["rollout_id"]["$ref"] = "#/$defs/missing"
        result = self.validate(schema=schema, expect_success=False)
        self.assertIn(b"unresolved local reference", result.stderr)

    def test_unknown_schema_keyword_fails_closed(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["x-unsupported-test-keyword"] = True
        result = self.validate(schema=schema, expect_success=False)
        self.assertIn(b"unsupported keywords", result.stderr)

    def test_extra_record_field_fails_closed(self) -> None:
        record = copy.deepcopy(self.record)
        record["extra"] = True
        self.validate(record=record, expect_success=False)

    def test_invalid_success_branch_fails_closed(self) -> None:
        record = copy.deepcopy(self.record)
        record["status"] = "succeeded"
        record["failure_stage"] = None
        record["rollback"] = None
        self.validate(record=record, expect_success=False)


def invariant_snapshot(baseline_sha256: str) -> dict[str, Any]:
    digest = "4" * 64
    return {
        "baseline_sha256": baseline_sha256,
        "containers": {
            name: {
                "cap_add": [],
                "cap_drop": [],
                "container_id": str(index) * 64,
                "devices_sha256": digest,
                "health": "healthy",
                "image_id": "sha256:" + str(index) * 64,
                "mounts_sha256": digest,
                "networks": ["sub2api-network"],
                "namespace_modes_sha256": digest,
                "no_new_privileges": True,
                "ports": ([] if name != "sub2api" else ["127.0.0.1:8080->8080/tcp"]),
                "privileged": False,
                "read_only_rootfs": True,
                "resource_access_sha256": digest,
                "restart_count": 0,
                "running": True,
                "security_opts_sha256": digest,
                "security_sha256": digest,
                "user_sha256": digest,
            }
            for index, name in enumerate(("sub2api", "postgres", "redis"), 7)
        },
        "format_version": 2,
        "listeners": ["127.0.0.1:18090", "127.0.0.1:18091", "127.0.0.1:18093"],
        "migration": {
            "at_expected_head": True,
            "current_revision": "20260101_0008",
            "expected_revision": "20260101_0008",
            "head_revision": "20260101_0008",
            "state_sha256": digest,
        },
        "nginx": {
            "effective_config_sha256": digest,
            "managed_tree_sha256": digest,
            "master_pid": 42,
            "restart_count": 0,
        },
        "postgres": {
            "control_database_acl_sha256": digest,
            "control_owned_relation_count": 1,
            "control_owned_schema_count": 1,
            "control_relation_acl_sha256": digest,
            "control_schema_acl_sha256": digest,
            "database": "codex_control",
            "database_owner": "codex_control",
            "public_connect_exception_recorded": False,
            "role": "codex_control",
            "role_bypass_rls": False,
            "role_create_db": False,
            "role_create_role": False,
            "role_inherit": False,
            "role_login": True,
            "role_membership_count": 0,
            "role_replication": False,
            "role_superuser": False,
            "sub2api_database": "sub2api",
            "sub2api_database_acl_sha256": digest,
            "sub2api_direct_database_acl_privilege_count": 0,
            "sub2api_direct_relation_acl_privilege_count": 0,
            "sub2api_direct_schema_acl_privilege_count": 0,
            "sub2api_effective_connect": False,
            "sub2api_effective_create": False,
            "sub2api_effective_relation_privilege_count": 0,
            "sub2api_effective_schema_create_privilege_count": 0,
            "sub2api_effective_sequence_privilege_count": 0,
            "sub2api_effective_temporary": False,
            "sub2api_owned_relation_count": 0,
            "sub2api_owned_schema_count": 0,
            "sub2api_public_connect": False,
        },
        "redis": {
            "auth_mode": "none",
            "configuration_projection_sha256": digest,
            "default_acl_sha256": digest,
            "namespace": {"channel_count": 0, "key_count": 0, "within_bounds": True},
            "prefix": "codex-control:",
            "runtime_acl_sha256": digest,
            "runtime_user": "default",
        },
        "schema_version": 1,
        "ufw": {"normalized_rules_sha256": "5" * 64, "status": "active"},
    }


class InvariantTests(TemporaryCase):
    def setUp(self) -> None:
        super().setUp()
        old_path = self.path(
            "invariants-old-compose.json", compose_config(OLD_RELEASE, OLD_VCS, OLD_IMAGES)
        )
        new_path = self.path(
            "invariants-new-compose.json", compose_config(NEW_RELEASE, NEW_VCS, NEW_IMAGES)
        )
        artifact_path = self.path("invariants-artifact.json", artifact_manifest())
        plan_result = self.run_admission(
            "plan",
            "--old-compose",
            str(old_path),
            "--new-compose",
            str(new_path),
            "--artifact-manifest",
            str(artifact_path),
        )
        self.plan_path = self.path("invariants-plan.json", json.loads(plan_result.stdout))
        plan_raw = self.plan_path.read_bytes()
        evidence = {"basename": "fixture.json", "sha256": "6" * 64, "size": 1}
        self.baseline_path = self.path(
            "invariants-baseline.json",
            {
                "archive_evidence_sha256": "6" * 64,
                "archives": {
                    component: {
                        "basename": ARCHIVE_NAMES[component],
                        "sha256": sha256(ARCHIVE_CONTENTS[component]),
                        "size": len(ARCHIVE_CONTENTS[component]),
                    }
                    for component in ARCHIVE_NAMES
                },
                "artifact_manifest_sha256": sha256(canonical_bytes(artifact_manifest())),
                "bootstrap_deployment": {
                    "deployment_basename": "bootstrap-20260812T134654Z-c536c183-26e4-4e8e-9e66-db57e7053501",
                    "deployment_id": "c536c183-26e4-4e8e-9e66-db57e7053501",
                },
                "bootstrap_record_sha256": "6" * 64,
                "bundle_evidence_sha256": "6" * 64,
                "closure_record_sha256": "6" * 64,
                "closure_target": {
                    "artifact_identity_sha256": "6" * 64,
                    "binding_sha256": "6" * 64,
                    "compose_plan_sha256": "6" * 64,
                    "local_images_sha256": "6" * 64,
                    "public_origin": "https://control.example.com",
                    "running_containers_sha256": "6" * 64,
                    "runtime_identity_sha256": "6" * 64,
                    "source_identity_sha256": "6" * 64,
                },
                "command": "baseline",
                "format_version": 1,
                "migration_state_sha256": "6" * 64,
                "migrations": {},
                "no_backup": True,
                "no_migration": True,
                "old_admission": {},
                "operator_exception_sha256": "6" * 64,
                "ready_record": {
                    "bundle_id": FIXTURE_BUNDLE_ID,
                    "sha256": sha256(canonical_bytes(ready_record())),
                    "transport_sha256": sha256(TRANSPORT_ARCHIVE_CONTENT),
                },
                "rollout_plan_sha256": sha256(plan_raw),
                "source_evidence": {},
                "status": "admitted",
                "tooling": {
                    "admission": evidence,
                    "admission_helper": evidence,
                    "archive": evidence,
                    "external_verifier": evidence,
                    "manifest": evidence,
                    "record_schema": evidence,
                    "root_owned_read_only": True,
                    "smoke_helper": evidence,
                    "tooling_identity": "6" * 64,
                    "wrapper": evidence,
                },
            },
        )
        self.baseline_sha256 = sha256(self.baseline_path.read_bytes())

    def invoke(
        self,
        before: Any,
        after: Any,
        *,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run_admission(
            "invariants",
            "--plan",
            str(self.plan_path),
            "--baseline",
            str(self.baseline_path),
            "--before",
            str(self.path("before.json", before)),
            "--after",
            str(self.path("after.json", after)),
            expect_success=expect_success,
        )

    def test_exact_projection_is_admitted(self) -> None:
        snapshot = invariant_snapshot(self.baseline_sha256)
        result = self.invoke(snapshot, copy.deepcopy(snapshot))
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, canonical_bytes(value))
        self.assertTrue(value["unchanged"])
        self.assertEqual(value["containers"], snapshot["containers"])

    def test_each_protected_projection_change_fails_closed(self) -> None:
        mutations: list[Callable[[dict[str, Any]], None]] = [
            lambda value: value["nginx"].update(effective_config_sha256="6" * 64),
            lambda value: value["ufw"].update(normalized_rules_sha256="6" * 64),
            lambda value: value["listeners"].append("0.0.0.0:8090"),
            lambda value: value["containers"]["sub2api"].update(container_id="1" * 64),
            lambda value: value["containers"]["postgres"].update(
                image_id="sha256:" + "1" * 64
            ),
            lambda value: value["containers"]["redis"].update(running=False),
            lambda value: value["containers"]["redis"]["networks"].append("wrong"),
            lambda value: value["containers"]["sub2api"]["ports"].append(
                "0.0.0.0:8080->8080/tcp"
            ),
        ]
        before = invariant_snapshot(self.baseline_sha256)
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                after = copy.deepcopy(before)
                mutate(after)
                self.invoke(before, after, expect_success=False)


if __name__ == "__main__":
    unittest.main()
