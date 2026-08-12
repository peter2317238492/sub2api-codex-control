from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL = REPO_ROOT / "deploy/scripts/map-oci-image-archive.py"
SPEC = importlib.util.spec_from_file_location("map_oci_image_archive", TOOL)
assert SPEC is not None and SPEC.loader is not None
ARCHIVE_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVE_MODULE)

TAG = "example/control-api:release-1"
PLATFORM = "linux/amd64"
LABELS = {
    "org.opencontainers.image.revision": "a" * 40,
    "org.opencontainers.image.source": "https://example.invalid/control",
    "org.opencontainers.image.version": "1.2.3",
}


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class OciArchiveIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oci-archive-map-tests.")
        self.root = Path(self.temporary.name)
        self.archive = self.root / "image.tar"
        self.fixture = self.write_archive()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_archive(
        self,
        *,
        tag: str = TAG,
        os_name: str = "linux",
        architecture: str = "amd64",
        labels: dict[str, str] | None = None,
        index_digest: str | None = None,
        config_digest: str | None = None,
        manifest_count: int = 1,
        corrupt_layer_blob: bool = False,
        extra_member: tuple[str, bytes, bytes] | None = None,
    ) -> dict[str, str]:
        selected_labels = LABELS if labels is None else labels
        layer_raw = b"deterministic image layer\n"
        layer_hex = hashlib.sha256(layer_raw).hexdigest()
        actual_layer_raw = layer_raw + b"corrupt" if corrupt_layer_blob else layer_raw
        config_raw = compact(
            {
                "architecture": architecture,
                "config": {"Labels": selected_labels},
                "os": os_name,
                "rootfs": {"diff_ids": [f"sha256:{layer_hex}"], "type": "layers"},
            }
        )
        config_hex = hashlib.sha256(config_raw).hexdigest()
        selected_config_digest = config_digest or f"sha256:{config_hex}"
        manifest_raw = compact(
            {
                "config": {
                    "digest": selected_config_digest,
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": len(config_raw),
                },
                "layers": [
                    {
                        "digest": f"sha256:{layer_hex}",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "size": len(layer_raw),
                    }
                ],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            }
        )
        manifest_hex = hashlib.sha256(manifest_raw).hexdigest()
        selected_manifest_digest = index_digest or f"sha256:{manifest_hex}"
        descriptor = {
            "annotations": {
                "io.containerd.image.name": f"docker.io/{tag}",
                "org.opencontainers.image.ref.name": tag.rsplit(":", 1)[1],
            },
            "digest": selected_manifest_digest,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "size": len(manifest_raw),
        }
        index_raw = compact(
            {
                "manifests": [descriptor for _ in range(manifest_count)],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        )
        manifest_json_raw = compact(
            [
                {
                    "Config": f"blobs/sha256/{config_hex}",
                    "Layers": [f"blobs/sha256/{layer_hex}"],
                    "RepoTags": [tag],
                }
            ]
        )
        members = [
            ("blobs", None, tarfile.DIRTYPE),
            ("blobs/sha256", None, tarfile.DIRTYPE),
            (f"blobs/sha256/{config_hex}", config_raw, tarfile.REGTYPE),
            (f"blobs/sha256/{layer_hex}", actual_layer_raw, tarfile.REGTYPE),
            (f"blobs/sha256/{manifest_hex}", manifest_raw, tarfile.REGTYPE),
            ("index.json", index_raw, tarfile.REGTYPE),
            ("manifest.json", manifest_json_raw, tarfile.REGTYPE),
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', tarfile.REGTYPE),
        ]
        if extra_member is not None:
            name, raw, member_type = extra_member
            members.append((name, raw, member_type))
        with tarfile.open(self.archive, "w") as archive:
            for name, raw, member_type in members:
                info = tarfile.TarInfo(name)
                info.mtime = 0
                info.mode = 0o755 if member_type == tarfile.DIRTYPE else 0o644
                info.type = member_type
                if member_type == tarfile.REGTYPE:
                    assert raw is not None
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
                else:
                    info.size = 0
                    archive.addfile(info)
        self.archive.chmod(0o600)
        return {
            "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "config_digest": f"sha256:{config_hex}",
            "index_sha256": f"sha256:{hashlib.sha256(index_raw).hexdigest()}",
            "layer_digest": f"sha256:{layer_hex}",
            "manifest_digest": f"sha256:{manifest_hex}",
        }

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "archive": self.archive,
            "expected_archive_sha256": self.fixture["archive_sha256"],
            "expected_tag": TAG,
            "expected_platform": PLATFORM,
            "expected_label": [f"{key}={value}" for key, value in LABELS.items()],
            "expected_manifest_digest": None,
            "expected_config_digest": None,
            "inspect_json": None,
            "docker_image": None,
            "docker": "docker",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def write_inspect(self, image_id: str, **overrides: object) -> Path:
        value: dict[str, object] = {
            "Architecture": "amd64",
            "Config": {"Labels": LABELS},
            "Id": image_id,
            "Os": "linux",
            "RepoTags": [TAG],
        }
        value.update(overrides)
        path = self.root / "inspect.json"
        path.write_text(json.dumps([value]), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_maps_archive_to_manifest_and_config_digests(self) -> None:
        result = ARCHIVE_MODULE.build_identity_map(self.args())
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["daemon"], None)
        self.assertEqual(result["archive"]["sha256"], self.fixture["archive_sha256"])
        self.assertEqual(
            result["image"]["manifest_digest"], self.fixture["manifest_digest"]
        )
        self.assertEqual(
            result["image"]["config_digest"], self.fixture["config_digest"]
        )
        self.assertEqual(result["image"]["index_sha256"], self.fixture["index_sha256"])
        self.assertEqual(
            result["image"]["layer_digests"], [self.fixture["layer_digest"]]
        )
        self.assertEqual(result["image"]["platform"], PLATFORM)
        self.assertEqual(result["image"]["labels"], LABELS)

    def test_normalizes_unqualified_and_registry_qualified_tags(self) -> None:
        self.assertEqual(
            ARCHIVE_MODULE.canonical_docker_tag("control-api:release-1"),
            "docker.io/library/control-api:release-1",
        )
        self.assertEqual(
            ARCHIVE_MODULE.canonical_docker_tag("example/control-api:release-1"),
            "docker.io/example/control-api:release-1",
        )
        self.assertEqual(
            ARCHIVE_MODULE.canonical_docker_tag(
                "registry.example:5000/control-api:release-1"
            ),
            "registry.example:5000/control-api:release-1",
        )

    def test_accepts_daemon_config_digest_id(self) -> None:
        inspect = self.write_inspect(self.fixture["config_digest"])
        result = ARCHIVE_MODULE.build_identity_map(self.args(inspect_json=inspect))
        self.assertEqual(result["daemon"]["id_kind"], "config-digest")

    def test_accepts_daemon_manifest_digest_id(self) -> None:
        inspect = self.write_inspect(self.fixture["manifest_digest"])
        result = ARCHIVE_MODULE.build_identity_map(self.args(inspect_json=inspect))
        self.assertEqual(result["daemon"]["id_kind"], "manifest-digest")

    def test_invokes_docker_only_when_requested(self) -> None:
        inspect_raw = json.dumps(
            [
                {
                    "Architecture": "amd64",
                    "Config": {"Labels": LABELS},
                    "Id": self.fixture["manifest_digest"],
                    "Os": "linux",
                    "RepoTags": [TAG],
                }
            ]
        ).encode("ascii")
        completed = subprocess.CompletedProcess(
            ["docker", "image", "inspect", TAG], 0, inspect_raw, b""
        )
        with mock.patch.object(
            ARCHIVE_MODULE.subprocess, "run", return_value=completed
        ) as run:
            result = ARCHIVE_MODULE.build_identity_map(
                self.args(docker_image=TAG, docker="/usr/bin/docker")
            )
        self.assertEqual(result["daemon"]["id_kind"], "manifest-digest")
        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0], ["/usr/bin/docker", "image", "inspect", TAG]
        )

    def test_rejects_wrong_archive_checksum_before_mapping(self) -> None:
        with self.assertRaisesRegex(
            ARCHIVE_MODULE.ArchiveIdentityError, "transport checksum"
        ):
            ARCHIVE_MODULE.build_identity_map(
                self.args(expected_archive_sha256="0" * 64)
            )

    def test_rejects_missing_index_manifest_blob(self) -> None:
        self.fixture = self.write_archive(index_digest=f"sha256:{'1' * 64}")
        with self.assertRaisesRegex(
            ARCHIVE_MODULE.ArchiveIdentityError, "missing image manifest"
        ):
            ARCHIVE_MODULE.build_identity_map(self.args())

    def test_rejects_missing_manifest_config_blob(self) -> None:
        self.fixture = self.write_archive(config_digest=f"sha256:{'2' * 64}")
        with self.assertRaisesRegex(
            ARCHIVE_MODULE.ArchiveIdentityError, "missing image config"
        ):
            ARCHIVE_MODULE.build_identity_map(self.args())

    def test_rejects_blob_whose_content_does_not_match_filename(self) -> None:
        self.fixture = self.write_archive(corrupt_layer_blob=True)
        with self.assertRaisesRegex(
            ARCHIVE_MODULE.ArchiveIdentityError, "blob content"
        ):
            ARCHIVE_MODULE.build_identity_map(self.args())

    def test_rejects_wrong_tag_platform_and_label(self) -> None:
        cases = (
            self.args(expected_tag="example/control-api:wrong"),
            self.args(expected_platform="linux/arm64"),
            self.args(expected_label=["org.opencontainers.image.version=9.9.9"]),
        )
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(ARCHIVE_MODULE.ArchiveIdentityError),
            ):
                ARCHIVE_MODULE.build_identity_map(arguments)

    def test_rejects_expected_digest_mismatch(self) -> None:
        for key in ("expected_manifest_digest", "expected_config_digest"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(
                    ARCHIVE_MODULE.ArchiveIdentityError, "expected digest"
                ),
            ):
                ARCHIVE_MODULE.build_identity_map(
                    self.args(**{key: f"sha256:{'3' * 64}"})
                )

    def test_rejects_ambiguous_multi_manifest_index(self) -> None:
        self.fixture = self.write_archive(manifest_count=2)
        with self.assertRaisesRegex(ARCHIVE_MODULE.ArchiveIdentityError, "exactly one"):
            ARCHIVE_MODULE.build_identity_map(self.args())

    def test_rejects_symlink_and_unexpected_archive_member(self) -> None:
        for extra in (
            ("escape", b"", tarfile.SYMTYPE),
            ("unexpected.txt", b"unexpected", tarfile.REGTYPE),
            ("index.json", b"{}", tarfile.REGTYPE),
        ):
            with self.subTest(extra=extra[0]):
                self.fixture = self.write_archive(extra_member=extra)
                with self.assertRaises(ARCHIVE_MODULE.ArchiveIdentityError):
                    ARCHIVE_MODULE.build_identity_map(self.args())

    def test_rejects_daemon_id_platform_labels_and_tag_drift(self) -> None:
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            (f"sha256:{'4' * 64}", {}),
            (self.fixture["config_digest"], {"Architecture": "arm64"}),
            (self.fixture["config_digest"], {"Config": {"Labels": {}}}),
            (
                self.fixture["config_digest"],
                {"RepoTags": ["example/other:tag"]},
            ),
        )
        for index, (image_id, overrides) in enumerate(cases):
            inspect = self.write_inspect(image_id, **overrides)
            with (
                self.subTest(index=index),
                self.assertRaises(ARCHIVE_MODULE.ArchiveIdentityError),
            ):
                ARCHIVE_MODULE.build_identity_map(self.args(inspect_json=inspect))

    def test_cli_emits_one_canonical_json_line(self) -> None:
        arguments = [
            sys.executable,
            str(TOOL),
            "--archive",
            str(self.archive),
            "--expected-archive-sha256",
            self.fixture["archive_sha256"],
            "--expected-tag",
            TAG,
            "--expected-platform",
            PLATFORM,
        ]
        for key, value in LABELS.items():
            arguments.extend(["--expected-label", f"{key}={value}"])
        result = subprocess.run(arguments, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, ARCHIVE_MODULE.canonical_json(value) + "\n")


if __name__ == "__main__":
    unittest.main()
