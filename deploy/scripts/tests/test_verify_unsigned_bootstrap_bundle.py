from __future__ import annotations

import gzip
import hashlib
import importlib.util
import inspect
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL = REPO_ROOT / "deploy/scripts/verify-unsigned-bootstrap-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_unsigned_bootstrap_bundle", TOOL)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)

EPOCH = 1_700_000_000
RELEASE = "0.1.0-bootstrap.20260812.5"
NGINX_LOG_PROVISIONER_HELPER = "deploy/scripts/provision-nginx-access-log.py"
NGINX_LOG_PROVISIONER = "deploy/scripts/provision-nginx-access-log.sh"
NGINX_REQUIRED_SOURCES = frozenset(
    {
        "deploy/nginx/api-security-headers.conf",
        "deploy/nginx/browser-security-headers.conf",
        "deploy/nginx/codex-control-access.logrotate",
        "deploy/nginx/hide-upstream-security-headers.conf",
        "deploy/nginx/http-context.conf",
        "deploy/nginx/server-locations.conf",
        "deploy/nginx/sub2api-logout-location.conf",
    }
)
NGINX_PROVISIONING_REQUIRED_SOURCES = NGINX_REQUIRED_SOURCES | frozenset(
    {NGINX_LOG_PROVISIONER_HELPER}
)


def compact_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_blob(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


class BundleFixture:
    def __init__(self, root: Path) -> None:
        self.bundle = root / "bundle"
        self.source = root / "source"
        self.bundle.mkdir(mode=0o700)
        self.source.mkdir(mode=0o700)
        self.contents = {
            path: f"fixture for {path}\n".encode()
            for path in VERIFY.EXECUTABLE_SOURCE_FILES
        }
        for path in VERIFY.REQUIRED_SOURCE_FILES:
            self.contents.setdefault(path, f"fixture for {path}\n".encode())
        self.contents[VERIFY.SUB2API_AUTH_CONTRACT_PATH] = (
            REPO_ROOT / VERIFY.SUB2API_AUTH_CONTRACT_PATH
        ).read_bytes()
        self.contents[VERIFY.SOURCE_VERIFIER_PATH] = TOOL.read_bytes()
        self.contents["README.md"] = b"ordinary source fixture\n"
        self.records = [
            VERIFY.SourceRecord(
                path=path,
                mode=0o555 if path in VERIFY.EXECUTABLE_SOURCE_FILES else 0o444,
                size=len(content),
                sha256=digest(content),
            )
            for path, content in sorted(
                self.contents.items(), key=lambda item: item[0].encode("utf-8")
            )
        ]
        for path, content in self.contents.items():
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o555 if path in VERIFY.EXECUTABLE_SOURCE_FILES else 0o444)
        for directory in sorted(
            (path for path in self.source.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        self.source.chmod(0o555)
        self.revision = digest(VERIFY.source_manifest_bytes(self.records))
        self.images: dict[str, dict[str, object]] = {}
        self.manifest: dict[str, object] = {}
        self.create()

    def write(self, name: str, raw: bytes) -> None:
        path = self.bundle / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def write_json(self, name: str, value: object) -> None:
        self.write(name, compact_json(value))

    def create_source_tar(
        self, *, wrong_mode: bool = False, executable_contract: bool = False
    ) -> None:
        destination = self.bundle / "source.tar.gz"
        directories = sorted(
            {
                parent.as_posix()
                for record in self.records
                for parent in PurePosixPath(record.path).parents
                if parent.as_posix() != "."
            },
            key=lambda value: value.encode("utf-8"),
        )
        with (
            destination.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=EPOCH
            ) as zipped,
            tarfile.open(
                fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT
            ) as archive,
        ):
            for directory in directories:
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o555
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = EPOCH
                archive.addfile(info)
            wrong_path = next(
                record.path for record in self.records if record.mode == 0o555
            )
            for record in self.records:
                info = tarfile.TarInfo(record.path)
                info.mode = (
                    0o555
                    if executable_contract
                    and record.path == VERIFY.SUB2API_AUTH_CONTRACT_PATH
                    else 0o444
                    if wrong_mode and record.path == wrong_path
                    else record.mode
                )
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = EPOCH
                info.size = record.size
                archive.addfile(info, io.BytesIO(self.contents[record.path]))
        destination.chmod(0o600)

    def create_image_archive(
        self,
        component: str,
        tag: str,
        labels: dict[str, str],
        user: str,
        *,
        corrupt_layer: bool = False,
    ) -> dict[str, object]:
        archive_name = VERIFY.ARCHIVE_NAMES[component]
        layer = f"fixture layer for {component}\n".encode("ascii")
        layer_digest = digest(layer)
        config_raw = json_blob(
            {
                "architecture": "amd64",
                "config": {"Labels": labels, "User": user},
                "os": "linux",
                "rootfs": {"diff_ids": [f"sha256:{layer_digest}"], "type": "layers"},
            }
        )
        config_digest = digest(config_raw)
        manifest_raw = json_blob(
            {
                "config": {
                    "digest": f"sha256:{config_digest}",
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": len(config_raw),
                },
                "layers": [
                    {
                        "digest": f"sha256:{layer_digest}",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "size": len(layer),
                    }
                ],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            }
        )
        manifest_digest = digest(manifest_raw)
        index_raw = json_blob(
            {
                "manifests": [
                    {
                        "annotations": {
                            "io.containerd.image.name": VERIFY.canonical_docker_tag(
                                tag
                            ),
                            "org.opencontainers.image.ref.name": tag.rsplit(":", 1)[1],
                        },
                        "digest": f"sha256:{manifest_digest}",
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"architecture": "amd64", "os": "linux"},
                        "size": len(manifest_raw),
                    }
                ],
                "mediaType": VERIFY.OCI_INDEX_MEDIA_TYPE,
                "schemaVersion": 2,
            }
        )
        legacy_raw = json_blob(
            [
                {
                    "Config": f"blobs/sha256/{config_digest}",
                    "Layers": [f"blobs/sha256/{layer_digest}"],
                    "RepoTags": [tag],
                }
            ]
        )
        members = {
            f"blobs/sha256/{config_digest}": config_raw,
            f"blobs/sha256/{layer_digest}": (
                b"corrupt" + layer if corrupt_layer else layer
            ),
            f"blobs/sha256/{manifest_digest}": manifest_raw,
            "index.json": index_raw,
            "manifest.json": legacy_raw,
            "oci-layout": json_blob({"imageLayoutVersion": "1.0.0"}),
        }
        archive_path = self.bundle / archive_name
        with tarfile.open(archive_path, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for directory in ("blobs", "blobs/sha256"):
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            for name, raw in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.mode = 0o644
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        archive_path.chmod(0o600)
        archive_sha = VERIFY.sha256_file(archive_path)
        return {
            "archive": {"sha256": archive_sha, "size": archive_path.stat().st_size},
            "image": {
                "config_digest": f"sha256:{config_digest}",
                "index_sha256": f"sha256:{digest(index_raw)}",
                "labels": labels,
                "layer_digests": [f"sha256:{layer_digest}"],
                "manifest_digest": f"sha256:{manifest_digest}",
                "platform": VERIFY.PLATFORM,
                "tag": tag,
                "verified_blob_count": 3,
            },
        }

    def create(self) -> None:
        identity_raw = VERIFY.source_manifest_bytes(self.records)
        source_list = VERIFY.expected_source_list(self.records)
        source_checksums = VERIFY.expected_source_checksums(self.records)
        self.write("source-files.manifest", identity_raw)
        self.write(
            "source-files.manifest.sha256",
            f"{self.revision}  source-files.manifest\n".encode("ascii"),
        )
        self.write("source-files.list", source_list)
        self.write("source-files.sha256", source_checksums)
        self.write(
            "source-files.sha256.sha256",
            f"{digest(source_checksums)}  source-files.sha256\n".encode("ascii"),
        )
        self.write("source-archive.list", VERIFY.expected_archive_list(self.records))
        self.create_source_tar()
        self.write(
            "source.tar.gz.sha256",
            f"{VERIFY.sha256_file(self.bundle / 'source.tar.gz')}  source.tar.gz\n".encode(
                "ascii"
            ),
        )
        self.write(
            "source-extraction-verify.log",
            "".join(f"{record.path}: OK\n" for record in self.records).encode("utf-8"),
        )
        self.write("docker-load-verification.log", b"three archives loaded\n")

        for index, component in enumerate(VERIFY.COMPONENTS, start=1):
            archive_name = VERIFY.ARCHIVE_NAMES[component]
            tag = f"sub2api-codex-{component}:bootstrap-{self.revision[:12]}"
            labels = {
                "org.opencontainers.image.revision": self.revision,
                "org.opencontainers.image.source": "sub2api-codex-control",
                "org.opencontainers.image.title": VERIFY.IMAGE_TITLES[component],
                "org.opencontainers.image.version": RELEASE,
            }
            user = next(iter(sorted(VERIFY.EXPECTED_USERS[component])))
            portable = self.create_image_archive(component, tag, labels, user)
            portable_image = portable["image"]
            assert isinstance(portable_image, dict)
            archive_identity = portable["archive"]
            assert isinstance(archive_identity, dict)
            config_digest = portable_image["config_digest"]
            image_id = config_digest
            archive_map = {
                "archive": archive_identity,
                "daemon": {
                    "id": image_id,
                    "id_kind": "config-digest",
                    "repo_tags": [tag],
                },
                "format_version": 1,
                "image": portable_image,
                "status": "verified",
            }
            map_name = f"{component}-archive-map.json"
            self.write_json(map_name, archive_map)
            inspect = [
                {
                    "Architecture": "amd64",
                    "Config": {
                        "Labels": labels,
                        "User": user,
                    },
                    "Id": image_id,
                    "Os": "linux",
                    "RepoTags": [tag],
                }
            ]
            self.write_json(f"{component}-image-inspect.json", inspect)
            metadata = {
                "archive_exporter": "docker",
                "build_args": {
                    "CONTROL_RELEASE": RELEASE,
                    "SOURCE_DATE_EPOCH": str(EPOCH),
                    "VCS_REF": self.revision,
                    **(
                        {"VITE_CONTROL_CSRF_COOKIE_NAME": "codex_csrf"}
                        if component == "pwa"
                        else {}
                    ),
                },
                "builder": "docker buildx",
                "daemon_image_id": image_id,
                "daemon_image_id_kind": "config-digest",
                "format_version": 2,
                "docker_versions": {
                    "buildx": "github.com/docker/buildx v0.fixture",
                    "client": "fixture",
                    "server": "fixture",
                },
                "platform_identity": {
                    "archive_mapper": VERIFY.PLATFORM,
                    "build_host_platform_is_not_image_evidence": True,
                    "daemon_inspect": VERIFY.PLATFORM,
                    "requested": VERIFY.PLATFORM,
                },
                "release": RELEASE,
                "revision": self.revision,
                "tag": tag,
            }
            metadata_name = f"{component}-build-metadata.json"
            self.write_json(metadata_name, metadata)
            build_log = f"{component}-build.log"
            self.write(build_log, f"built {component}\n".encode("ascii"))
            self.images[component] = {
                "archive": archive_name,
                "archive_sha256": archive_identity["sha256"],
                "archive_size": archive_identity["size"],
                "build_log": build_log,
                "build_log_sha256": VERIFY.sha256_file(self.bundle / build_log),
                "build_metadata": metadata_name,
                "build_metadata_sha256": VERIFY.sha256_file(
                    self.bundle / metadata_name
                ),
                "config_digest": config_digest,
                "daemon_image_id": image_id,
                "daemon_image_id_kind": "config-digest",
                "index_sha256": portable_image["index_sha256"],
                "manifest_digest": portable_image["manifest_digest"],
                "mapper_manifest": map_name,
                "mapper_manifest_sha256": VERIFY.sha256_file(self.bundle / map_name),
                "oci_labels": labels,
                "platform": VERIFY.PLATFORM,
                "tag": tag,
            }

        pwa_runtime = {
            "cleanup": {
                "containers_removed": True,
                "network_removed": True,
            },
            "configured_user": "nginx",
            "format_version": 3,
            "host_health": {
                "body": "ok",
                "path": "/healthz",
                "status_code": 200,
            },
            "image_id": self.images["pwa"]["daemon_image_id"],
            "image_tag": self.images["pwa"]["tag"],
            "network": {
                "attachable": False,
                "container_id": "d" * 64,
                "driver": "bridge",
                "enable_ipv6": False,
                "id": "a" * 64,
                "inspect_topology_exact": True,
                "internal": False,
                "name": "sub2api-bundle-pwa-net-1234-deadbeef",
                "options": {
                    "com.docker.network.bridge.enable_icc": "false",
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                },
                "sole_member": True,
            },
            "nginx_config": {
                "mode": "444",
                "path": "/etc/nginx/nginx.conf",
                "readable_by_runtime_user": True,
            },
            "port_mapping": {
                "container_port": 8080,
                "host_ip": "127.0.0.1",
                "host_port": 49152,
                "inherited_unpublished_ports": ["80/tcp"],
                "inspect_mapping_exact": True,
                "protocol": "tcp",
            },
            "runtime": {
                "container_id": "d" * 64,
                "docker_health_status": "healthy",
                "healthz_body": "ok",
                "process_started_from_image_entrypoint": True,
            },
            "runtime_uid": 101,
            "status": "verified",
        }
        self.write_json("pwa-runtime-verification.json", pwa_runtime)
        self.images["pwa"]["runtime_verification"] = {
            "file": "pwa-runtime-verification.json",
            "result": pwa_runtime,
            "sha256": VERIFY.sha256_file(self.bundle / "pwa-runtime-verification.json"),
        }

        versions_raw = "".join(
            f"{line}\n" for line in VERIFY.EXPECTED_POSTGRES_VERSIONS
        ).encode("ascii")
        self.write("postgres-tools-version.txt", versions_raw)
        fixture_identity = {
            "canonical_rows_sha256": "6" * 64,
            "row_count": 2,
            "schema_sha256": "7" * 64,
            "sequence_last_value": 42,
        }
        roundtrip = {
            "cleanup": {
                "containers_removed": True,
                "network_removed": True,
                "persistent_volume_created": False,
            },
            "dump": {
                "format": "custom",
                "list_entry_count": 5,
                "list_sha256": "4" * 64,
                "sha256": "5" * 64,
                "size": 4096,
            },
            "fixture": {
                "restored": dict(fixture_identity),
                "schema": "bundle_fixture",
                "sequence": "item_seq",
                "source": dict(fixture_identity),
                "source_and_restored_rows_equal": True,
                "source_and_restored_schema_equal": True,
                "table": "items",
            },
            "format_version": 1,
            "isolation": {
                "docker_internal_network": True,
                "password_authentication_used": False,
                "persistent_volume_used": False,
                "server_pgdata": "tmpfs",
            },
            "server": {
                "dockerfile_base_image_material": VERIFY.POSTGRES_SERVER_IMAGE,
                "image_id": self.images["postgres-tools"]["daemon_image_id"],
                "image_tag": self.images["postgres-tools"]["tag"],
                "version": "18.4",
            },
            "status": "verified",
            "tools": {
                "client_versions": VERIFY.EXPECTED_POSTGRES_VERSIONS,
                "image_id": self.images["postgres-tools"]["daemon_image_id"],
                "image_tag": self.images["postgres-tools"]["tag"],
            },
        }
        self.write_json("postgres-tools-dump-restore-verification.json", roundtrip)
        self.images["postgres-tools"]["client_versions"] = (
            VERIFY.EXPECTED_POSTGRES_VERSIONS
        )
        self.images["postgres-tools"]["dump_restore_verification"] = {
            "file": "postgres-tools-dump-restore-verification.json",
            "result": roundtrip,
            "sha256": VERIFY.sha256_file(
                self.bundle / "postgres-tools-dump-restore-verification.json"
            ),
        }

        image_checksum_names = [
            VERIFY.ARCHIVE_NAMES[component] for component in VERIFY.COMPONENTS
        ]
        self.write(
            "bootstrap-images.sha256",
            "".join(
                f"{VERIFY.sha256_file(self.bundle / name)}  {name}\n"
                for name in image_checksum_names
            ).encode("ascii"),
        )
        self.write(
            "transport-SHA256SUMS",
            "".join(
                f"{VERIFY.sha256_file(self.bundle / name)}  {name}\n"
                for name in ["source.tar.gz", *image_checksum_names]
            ).encode("ascii"),
        )
        self.manifest = {
            "artifact_kind": "unsigned-production-bootstrap-images",
            "build": {
                "archive_exporter": "docker",
                "normalized_source_context": {
                    "content_hashes_verified_after_normalization": True,
                    "directory_mode": "0555",
                    "regular_file_mode": "0444",
                },
                "platform": VERIFY.PLATFORM,
                "platform_evidence": "OCI mapper plus daemon image inspect",
            },
            "format_version": 5,
            "generated_at": "2023-11-14T22:13:20Z",
            "images": self.images,
            "offline_verifier": {
                "file": VERIFY.BUNDLE_VERIFIER_FILE,
                "mode": "0600",
                "sha256": digest(TOOL.read_bytes()),
            },
            "release": RELEASE,
            "schema_version": 1,
            "source": {
                "archive": {
                    "apple_double_free": True,
                    "file": "source.tar.gz",
                    "sha256": VERIFY.sha256_file(self.bundle / "source.tar.gz"),
                    "size": (self.bundle / "source.tar.gz").stat().st_size,
                },
                "canonical_hash_manifest": {
                    "file": "source-files.manifest",
                    "is_vcs_ref": True,
                    "sha256": self.revision,
                },
                "canonical_hash_manifest_format": "normalized-mode-space-size-space-sha256-two-spaces-relative-path-lf-sorted-by-utf8-path",
                "enumeration": "complete filesystem traversal with explicit exclusions",
                "explicit_exclusions": VERIFY.exclusion_policy(),
                "file_count": len(self.records),
                "file_list": {
                    "file": "source-files.list",
                    "format": "normalized-mode-space-size-two-spaces-relative-path",
                    "sha256": VERIFY.sha256_file(self.bundle / "source-files.list"),
                },
                "normalized_modes": {
                    "directories": "0555",
                    "executable_allowlist": "0555",
                    "other_regular_files": "0444",
                },
                "sha256sum_compatible_content_manifest": {
                    "file": "source-files.sha256",
                    "sha256": VERIFY.sha256_file(self.bundle / "source-files.sha256"),
                },
            },
            "status": "ready",
            "transport": {
                "apple_double_free": True,
                "checksum_file": "transport-SHA256SUMS",
                "checksum_file_sha256": VERIFY.sha256_file(
                    self.bundle / "transport-SHA256SUMS"
                ),
                "image_checksum_file": "bootstrap-images.sha256",
                "image_checksum_file_sha256": VERIFY.sha256_file(
                    self.bundle / "bootstrap-images.sha256"
                ),
                "docker_load_verified": True,
            },
            "trust_mode": "unsigned-first-deployment-v1",
            "vcs_ref": self.revision,
            "verification": {
                "bundle_checksum_closure_excludes_only_SHA256SUMS_itself": True,
                "image_archives_are_docker_loadable": True,
                "image_archives_map_verified_twice_with_pinned_manifest_and_config_digests": True,
                "image_ids_platform_tags_and_labels_match": True,
                "normalized_context_content_matches_source_manifest": True,
                "postgres_dump_restore_18_4": True,
                "pwa_non_root_nginx_config_readable_and_runtime_healthy": True,
                "source_archive_matches_file_list": True,
                "source_extraction_matches_canonical_hash_manifest": True,
                "source_tree_unchanged_before_atomic_publish": True,
            },
        }
        self.write(VERIFY.BUNDLE_VERIFIER_FILE, TOOL.read_bytes())
        self.write_manifests()
        self.refresh_closure()

    def write_manifests(self) -> None:
        self.write_json("artifact-manifest.json", self.manifest)
        self.write_json("artifacts-manifest.json", self.manifest)
        for name in ("artifact-manifest.json", "artifacts-manifest.json"):
            self.write(
                f"{name.removesuffix('.json')}.sha256",
                f"{VERIFY.sha256_file(self.bundle / name)}  {name}\n".encode("ascii"),
            )

    def refresh_closure(self) -> None:
        names = sorted(
            path.name for path in self.bundle.iterdir() if path.name != "SHA256SUMS"
        )
        raw = "".join(
            f"{VERIFY.sha256_file(self.bundle / name)}  {name}\n" for name in names
        ).encode("ascii")
        path = self.bundle / "SHA256SUMS"
        path.write_bytes(raw)
        path.chmod(0o600)

    def create_transport(self, destination: Path) -> None:
        with tarfile.open(destination, mode="w", format=tarfile.PAX_FORMAT) as archive:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            root.mode = 0o700
            root.uid = root.gid = 0
            root.uname = root.gname = "root"
            root.mtime = EPOCH
            archive.addfile(root)
            for source in sorted(
                self.bundle.iterdir(), key=lambda path: path.name.encode("utf-8")
            ):
                info = tarfile.TarInfo(source.name)
                info.mode = 0o600
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = EPOCH
                info.size = source.stat().st_size
                with source.open("rb") as handle:
                    archive.addfile(info, handle)
        destination.chmod(0o600)


def extract_private_transport(transport: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tarfile.open(transport, mode="r:") as archive:
        for member in archive:
            if member.name == ".":
                continue
            target = destination / member.name
            extracted = archive.extractfile(member)
            assert extracted is not None
            target.write_bytes(extracted.read())
            target.chmod(0o600)


class UnsignedBootstrapBundleVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bundle-verifier-tests.")
        self.fixture = BundleFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify_fixture_source(self) -> dict[str, object]:
        return VERIFY.verify_bundle(
            self.fixture.bundle,
            self.fixture.source,
            expected_bundle_uid=os.geteuid(),
            expected_bundle_gid=os.getegid(),
            bundle_trust_anchor=Path(self.temporary.name),
            expected_source_uid=os.geteuid(),
            expected_source_gid=os.getegid(),
            source_trust_anchor=Path(self.temporary.name),
        )

    def verify_fixture_archive(self) -> dict[str, object]:
        return VERIFY.verify_bundle(
            self.fixture.bundle,
            expected_bundle_uid=os.geteuid(),
            expected_bundle_gid=os.getegid(),
            bundle_trust_anchor=Path(self.temporary.name),
        )

    def mutate_pwa_runtime(self, mutate: object) -> None:
        name = "pwa-runtime-verification.json"
        value = json.loads((self.fixture.bundle / name).read_text(encoding="ascii"))
        assert callable(mutate)
        mutate(value)
        self.fixture.write_json(name, value)
        pwa = self.fixture.manifest["images"]["pwa"]  # type: ignore[index]
        descriptor = pwa["runtime_verification"]
        descriptor["result"] = value
        descriptor["sha256"] = VERIFY.sha256_file(self.fixture.bundle / name)
        self.fixture.write_manifests()
        self.fixture.refresh_closure()

    def test_verifies_complete_bundle_and_matching_source_root(self) -> None:
        result = self.verify_fixture_source()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["vcs_ref"], self.fixture.revision)
        self.assertEqual(result["source_file_count"], len(self.fixture.records))
        self.assertTrue(result["source_root_verified"])

        contract = next(
            record
            for record in self.fixture.records
            if record.path == VERIFY.SUB2API_AUTH_CONTRACT_PATH
        )
        self.assertIn(contract.path, VERIFY.REQUIRED_SOURCE_FILES)
        self.assertNotIn(contract.path, VERIFY.EXECUTABLE_SOURCE_FILES)
        self.assertEqual(contract.mode, 0o444)
        manifest_line = next(
            line
            for line in (self.fixture.bundle / "source-files.manifest")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.endswith(f"  {contract.path}")
        )
        self.assertTrue(manifest_line.startswith("0444 "))
        with tarfile.open(self.fixture.bundle / "source.tar.gz", "r:gz") as archive:
            self.assertEqual(archive.getmember(contract.path).mode, 0o444)
        self.assertEqual(
            stat.S_IMODE((self.fixture.source / contract.path).stat().st_mode),
            0o444,
        )

    def test_production_source_identity_rejects_user_owned_fixture(self) -> None:
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            "owned by the expected identity",
        ):
            VERIFY.verify_bundle(
                self.fixture.bundle,
                self.fixture.source,
                expected_bundle_uid=os.geteuid(),
                expected_bundle_gid=os.getegid(),
                bundle_trust_anchor=Path(self.temporary.name),
                expected_source_uid=os.geteuid() + 1,
                expected_source_gid=os.getegid(),
                source_trust_anchor=Path(self.temporary.name),
            )

    def test_bundle_verification_rejects_symlinked_or_writable_ancestor(self) -> None:
        root = Path(self.temporary.name)
        writable = root / "writable"
        writable.mkdir(mode=0o700)
        linked = writable / "linked"
        linked.symlink_to(self.fixture.bundle, target_is_directory=True)
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "securely open trusted bundle path"
        ):
            VERIFY.verify_bundle(
                linked,
                expected_bundle_uid=os.geteuid(),
                expected_bundle_gid=os.getegid(),
                bundle_trust_anchor=root,
            )

        original_mode = stat.S_IMODE(root.stat().st_mode)
        try:
            root.chmod(0o775)
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "every trusted ancestor.*not group or world writable",
            ):
                VERIFY.verify_bundle(
                    self.fixture.bundle,
                    expected_bundle_uid=os.geteuid(),
                    expected_bundle_gid=os.getegid(),
                    bundle_trust_anchor=root,
                )
        finally:
            root.chmod(original_mode)

    def test_source_verification_rejects_writable_trusted_ancestor(self) -> None:
        anchor = Path(self.temporary.name)
        original_mode = stat.S_IMODE(anchor.stat().st_mode)
        try:
            anchor.chmod(0o775)
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "every trusted ancestor.*not group or world writable",
            ):
                self.verify_fixture_source()
        finally:
            anchor.chmod(original_mode)

    def test_nginx_required_source_policy_is_exact(self) -> None:
        self.assertEqual(VERIFY.NGINX_REQUIRED_SOURCE_FILES, NGINX_REQUIRED_SOURCES)
        self.assertEqual(
            VERIFY.NGINX_PROVISIONER_HELPER_PATH,
            NGINX_LOG_PROVISIONER_HELPER,
        )
        self.assertEqual(
            VERIFY.NGINX_PROVISIONING_REQUIRED_SOURCE_FILES,
            NGINX_PROVISIONING_REQUIRED_SOURCES,
        )
        self.assertIn(NGINX_LOG_PROVISIONER_HELPER, VERIFY.REQUIRED_SOURCE_FILES)
        self.assertNotIn(NGINX_LOG_PROVISIONER_HELPER, VERIFY.EXECUTABLE_SOURCE_FILES)
        self.assertIn(NGINX_LOG_PROVISIONER, VERIFY.EXECUTABLE_SOURCE_FILES)
        self.assertEqual(
            {
                path
                for path in VERIFY.REQUIRED_SOURCE_FILES
                if path.startswith("deploy/nginx/")
            },
            NGINX_REQUIRED_SOURCES,
        )

    def test_rejects_each_missing_nginx_provisioning_source(self) -> None:
        for relative in sorted(NGINX_PROVISIONING_REQUIRED_SOURCES):
            with self.subTest(relative=relative):
                records = [
                    record for record in self.fixture.records if record.path != relative
                ]
                with self.assertRaisesRegex(
                    VERIFY.VerificationError,
                    rf"missing required inputs.*{relative.replace('.', r'\.')}",
                ):
                    VERIFY.parse_source_manifest(VERIFY.source_manifest_bytes(records))

    def test_rejects_missing_or_nonexecutable_nginx_launcher(self) -> None:
        records = [
            record
            for record in self.fixture.records
            if record.path != NGINX_LOG_PROVISIONER
        ]
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            "missing static executable inputs.*provision-nginx-access-log",
        ):
            VERIFY.parse_source_manifest(VERIFY.source_manifest_bytes(records))

        records = [
            VERIFY.SourceRecord(
                record.path,
                0o444 if record.path == NGINX_LOG_PROVISIONER else record.mode,
                record.size,
                record.sha256,
            )
            for record in self.fixture.records
        ]
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            "static allowlist.*provision-nginx-access-log",
        ):
            VERIFY.parse_source_manifest(VERIFY.source_manifest_bytes(records))

    def test_rejects_each_nginx_provisioning_source_with_executable_mode(
        self,
    ) -> None:
        for relative in sorted(NGINX_PROVISIONING_REQUIRED_SOURCES):
            with self.subTest(relative=relative):
                records = [
                    VERIFY.SourceRecord(
                        record.path,
                        0o555 if record.path == relative else record.mode,
                        record.size,
                        record.sha256,
                    )
                    for record in self.fixture.records
                ]
                with self.assertRaisesRegex(
                    VERIFY.VerificationError,
                    rf"static allowlist: {relative.replace('.', r'\.')}",
                ):
                    VERIFY.parse_source_manifest(VERIFY.source_manifest_bytes(records))

    def test_cli_verify_emits_one_json_result(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "verify-archive",
                "--bundle",
                str(self.fixture.bundle),
                "--bundle-trust-anchor",
                str(Path(self.temporary.name)),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["release"], RELEASE)
        self.assertFalse(value["source_root_verified"])
        self.assertFalse(value["admission"])
        self.assertEqual(value["status"], "archive-verified-non-admission")

    def test_cli_verify_requires_source_root_and_emits_no_admission(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "verify", "--bundle", str(self.fixture.bundle)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--source-root", result.stderr)

    def test_cli_identity_defaults_keep_archive_nonadmitting_and_source_root_owned(
        self,
    ) -> None:
        parameters = inspect.signature(VERIFY.verify_bundle).parameters
        self.assertIsNone(parameters["expected_bundle_uid"].default)
        self.assertIsNone(parameters["expected_bundle_gid"].default)
        self.assertEqual(parameters["bundle_trust_anchor"].default, Path("/"))
        self.assertEqual(parameters["expected_source_uid"].default, 0)
        self.assertEqual(parameters["expected_source_gid"].default, 0)
        self.assertEqual(parameters["source_trust_anchor"].default, Path("/"))

        if os.geteuid() != 0 or os.getegid() != 0:
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--bundle",
                    str(self.fixture.bundle),
                    "--bundle-trust-anchor",
                    str(Path(self.temporary.name)),
                    "--source-root",
                    str(self.fixture.source),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("owned by the expected identity", result.stderr)

    def test_runbooks_stage_and_admit_source_before_privileged_work(self) -> None:
        deployment = (REPO_ROOT / "docs/runbooks/deployment.md").read_text(
            encoding="utf-8"
        )
        unsigned = (REPO_ROOT / "docs/runbooks/unsigned-bootstrap.md").read_text(
            encoding="utf-8"
        )
        readme = (REPO_ROOT / "deploy/README.md").read_text(encoding="utf-8")

        staging = deployment.index("### Immutable source staging")
        archive_gate = deployment.index("verify-archive --bundle", staging)
        extraction = deployment.index("/usr/bin/tar --extract", archive_gate)
        source_gate = deployment.index('"$trusted_verifier" verify', extraction)
        first_later_privileged = deployment.index(
            "sudo install -d -o root -g root -m 0700", source_gate
        )
        self.assertLess(archive_gate, extraction)
        self.assertLess(extraction, source_gate)
        self.assertLess(source_gate, first_later_privileged)
        self.assertIn("--bundle-trust-anchor /", deployment)
        self.assertIn("ACTIVE_SOURCE", deployment)
        self.assertIn("ACTIVE_SOURCE", unsigned)
        self.assertIn("verify-archive", readme)
        self.assertIn('reports `"admission":false`', readme)
        for content in (deployment, unsigned):
            self.assertNotIn("CONTROL_TRUSTED_SOURCE_ROOT", content)
            self.assertNotIn("sudo python3", content)

    def test_extracted_transport_runs_bundled_verifier_and_rejects_tamper(self) -> None:
        root = Path(self.temporary.name)
        transport = root / "production-bootstrap-fixture.tar"
        extracted = root / "extracted"
        self.fixture.create_transport(transport)
        extract_private_transport(transport, extracted)
        verifier = extracted / VERIFY.BUNDLE_VERIFIER_FILE
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "verify-archive",
                "--bundle",
                str(extracted),
                "--bundle-trust-anchor",
                str(root),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["status"], "archive-verified-non-admission"
        )

        (extracted / "control-api-build.log").write_bytes(b"tampered\n")
        tampered = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "verify-archive",
                "--bundle",
                str(extracted),
                "--bundle-trust-anchor",
                str(root),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(tampered.returncode, 1)
        self.assertIn("bundle checksum mismatch", tampered.stderr)
        self.assertNotIn("Traceback", tampered.stderr)

    def test_rejects_offline_verifier_rebinding(self) -> None:
        descriptor = self.fixture.manifest["offline_verifier"]
        assert isinstance(descriptor, dict)
        descriptor["sha256"] = "f" * 64
        self.fixture.write_manifests()
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "verifier bundle binding"
        ):
            self.verify_fixture_archive()

    def test_rejects_corrupt_oci_blob_with_refreshed_outer_hashes(self) -> None:
        component = "pwa"
        image = self.fixture.images[component]
        labels = image["oci_labels"]
        assert isinstance(labels, dict)
        portable = self.fixture.create_image_archive(
            component,
            str(image["tag"]),
            labels,
            "101",
            corrupt_layer=True,
        )
        archive_identity = portable["archive"]
        assert isinstance(archive_identity, dict)
        image["archive_sha256"] = archive_identity["sha256"]
        image["archive_size"] = archive_identity["size"]
        map_name = str(image["mapper_manifest"])
        mapped = json.loads(
            (self.fixture.bundle / map_name).read_text(encoding="ascii")
        )
        mapped["archive"] = archive_identity
        self.fixture.write_json(map_name, mapped)
        image["mapper_manifest_sha256"] = VERIFY.sha256_file(
            self.fixture.bundle / map_name
        )
        self.fixture.write(
            "bootstrap-images.sha256",
            "".join(
                f"{VERIFY.sha256_file(self.fixture.bundle / VERIFY.ARCHIVE_NAMES[name])}  "
                f"{VERIFY.ARCHIVE_NAMES[name]}\n"
                for name in VERIFY.COMPONENTS
            ).encode("ascii"),
        )
        self.fixture.write(
            "transport-SHA256SUMS",
            "".join(
                f"{VERIFY.sha256_file(self.fixture.bundle / name)}  {name}\n"
                for name in [
                    "source.tar.gz",
                    *(VERIFY.ARCHIVE_NAMES[name] for name in VERIFY.COMPONENTS),
                ]
            ).encode("ascii"),
        )
        transport = self.fixture.manifest["transport"]
        assert isinstance(transport, dict)
        transport["checksum_file_sha256"] = VERIFY.sha256_file(
            self.fixture.bundle / "transport-SHA256SUMS"
        )
        transport["image_checksum_file_sha256"] = VERIFY.sha256_file(
            self.fixture.bundle / "bootstrap-images.sha256"
        )
        self.fixture.write_manifests()
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(VERIFY.VerificationError, "blob content differs"):
            self.verify_fixture_archive()

    def test_rejects_tampered_or_unlisted_bundle_file(self) -> None:
        (self.fixture.bundle / "control-api-build.log").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "checksum mismatch"):
            self.verify_fixture_archive()

        self.fixture.write("unlisted.txt", b"unlisted\n")
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "exact bundle file inventory"
        ):
            self.verify_fixture_archive()

    def test_rejects_noncanonical_source_mode_even_with_refreshed_closure(self) -> None:
        manifest = (self.fixture.bundle / "source-files.manifest").read_bytes()
        manifest = manifest.replace(b"0555 ", b"0444 ", 1)
        self.fixture.write("source-files.manifest", manifest)
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(VERIFY.VerificationError, "static allowlist"):
            self.verify_fixture_archive()

    def test_rejects_auth_contract_executable_mode_in_manifest(self) -> None:
        path = self.fixture.bundle / "source-files.manifest"
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.endswith(f"  {VERIFY.SUB2API_AUTH_CONTRACT_PATH}\n"):
                self.assertTrue(line.startswith("0444 "))
                lines[index] = "0555 " + line[5:]
                break
        else:  # pragma: no cover - fixture construction invariant
            self.fail("auth contract is absent from fixture manifest")
        self.fixture.write("source-files.manifest", "".join(lines).encode("utf-8"))
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            rf"static allowlist: {VERIFY.SUB2API_AUTH_CONTRACT_PATH}",
        ):
            self.verify_fixture_archive()

    def test_rejects_missing_auth_contract_from_manifest(self) -> None:
        records = [
            record
            for record in self.fixture.records
            if record.path != VERIFY.SUB2API_AUTH_CONTRACT_PATH
        ]
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            rf"missing required inputs.*{VERIFY.SUB2API_AUTH_CONTRACT_PATH}",
        ):
            VERIFY.parse_source_manifest(VERIFY.source_manifest_bytes(records))

    def test_rejects_source_archive_mode_mismatch(self) -> None:
        self.fixture.create_source_tar(wrong_mode=True)
        tar_sha = VERIFY.sha256_file(self.fixture.bundle / "source.tar.gz")
        self.fixture.write(
            "source.tar.gz.sha256",
            f"{tar_sha}  source.tar.gz\n".encode("ascii"),
        )
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(VERIFY.VerificationError, "mode or size"):
            self.verify_fixture_archive()

    def test_rejects_auth_contract_executable_mode_in_source_archive(self) -> None:
        self.fixture.create_source_tar(executable_contract=True)
        tar_sha = VERIFY.sha256_file(self.fixture.bundle / "source.tar.gz")
        self.fixture.write(
            "source.tar.gz.sha256",
            f"{tar_sha}  source.tar.gz\n".encode("ascii"),
        )
        source = self.fixture.manifest["source"]
        assert isinstance(source, dict)
        archive_descriptor = source["archive"]
        assert isinstance(archive_descriptor, dict)
        archive_descriptor["sha256"] = tar_sha
        archive_descriptor["size"] = (
            (self.fixture.bundle / "source.tar.gz").stat().st_size
        )
        self.fixture.write(
            "transport-SHA256SUMS",
            "".join(
                f"{VERIFY.sha256_file(self.fixture.bundle / name)}  {name}\n"
                for name in [
                    "source.tar.gz",
                    *(VERIFY.ARCHIVE_NAMES[name] for name in VERIFY.COMPONENTS),
                ]
            ).encode("ascii"),
        )
        transport = self.fixture.manifest["transport"]
        assert isinstance(transport, dict)
        transport["checksum_file_sha256"] = VERIFY.sha256_file(
            self.fixture.bundle / "transport-SHA256SUMS"
        )
        self.fixture.write_manifests()
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            rf"mode or size differs.*{VERIFY.SUB2API_AUTH_CONTRACT_PATH}",
        ):
            self.verify_fixture_archive()

    def test_rejects_auth_contract_executable_mode_in_source_root(self) -> None:
        contract = self.fixture.source / VERIFY.SUB2API_AUTH_CONTRACT_PATH
        contract.chmod(0o555)
        with self.assertRaisesRegex(
            VERIFY.VerificationError,
            rf"not normalized: {VERIFY.SUB2API_AUTH_CONTRACT_PATH}: expected 0444",
        ):
            self.verify_fixture_source()

    def test_rejects_mapper_identity_mismatch_after_all_hashes_are_refreshed(
        self,
    ) -> None:
        name = "pwa-archive-map.json"
        value = json.loads((self.fixture.bundle / name).read_text(encoding="ascii"))
        value["image"]["platform"] = "linux/arm64"
        self.fixture.write_json(name, value)
        image = self.fixture.manifest["images"]["pwa"]  # type: ignore[index]
        image["mapper_manifest_sha256"] = VERIFY.sha256_file(self.fixture.bundle / name)
        self.fixture.write_manifests()
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "mapper evidence differs"
        ):
            self.verify_fixture_archive()

    def test_cli_rejects_malformed_inspect_types_without_traceback(self) -> None:
        name = "pwa-image-inspect.json"
        value = json.loads((self.fixture.bundle / name).read_text(encoding="ascii"))
        value[0]["RepoTags"] = 1
        self.fixture.write_json(name, value)
        self.fixture.refresh_closure()
        result = subprocess.run(
            [
                sys.executable,
                str(self.fixture.bundle / VERIFY.BUNDLE_VERIFIER_FILE),
                "verify-archive",
                "--bundle",
                str(self.fixture.bundle),
                "--bundle-trust-anchor",
                str(Path(self.temporary.name)),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid field types", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_rejects_unverified_postgres_roundtrip_semantics(self) -> None:
        name = "postgres-tools-dump-restore-verification.json"
        value = json.loads((self.fixture.bundle / name).read_text(encoding="ascii"))
        value["fixture"]["restored"]["row_count"] += 1
        self.fixture.write_json(name, value)
        postgres = self.fixture.manifest["images"]["postgres-tools"]  # type: ignore[index]
        descriptor = postgres["dump_restore_verification"]
        descriptor["result"] = value
        descriptor["sha256"] = VERIFY.sha256_file(self.fixture.bundle / name)
        self.fixture.write_manifests()
        self.fixture.refresh_closure()
        with self.assertRaisesRegex(
            VERIFY.VerificationError, "fixture identities differ"
        ):
            self.verify_fixture_archive()

    def test_rejects_unverified_pwa_runtime_network_semantics(self) -> None:
        cases = {
            "public host binding": lambda value: value["port_mapping"].update(
                {"host_ip": "0.0.0.0"}
            ),
            "masquerade enabled": lambda value: value["network"]["options"].update(
                {"com.docker.network.bridge.enable_ip_masquerade": "true"}
            ),
            "internal network": lambda value: value["network"].update(
                {"internal": True}
            ),
            "extra network member": lambda value: value["network"].update(
                {"sole_member": False}
            ),
            "host unhealthy": lambda value: value["host_health"].update(
                {"status_code": 503}
            ),
            "cleanup incomplete": lambda value: value["cleanup"].update(
                {"network_removed": False}
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                root = Path(self.temporary.name) / label.replace(" ", "-")
                root.mkdir(mode=0o700)
                fixture = BundleFixture(root)
                self.fixture = fixture
                self.mutate_pwa_runtime(mutate)
                with self.assertRaisesRegex(
                    VERIFY.VerificationError,
                    "PWA runtime evidence does not satisfy the admitted gate",
                ):
                    self.verify_fixture_archive()

    def test_rejects_extra_pwa_runtime_evidence_key(self) -> None:
        self.mutate_pwa_runtime(lambda value: value.update({"unexpected": True}))
        with self.assertRaisesRegex(VERIFY.VerificationError, "keys mismatch"):
            self.verify_fixture_archive()

    def test_rejects_source_root_content_drift(self) -> None:
        target = self.fixture.source / "README.md"
        target.chmod(0o644)
        target.write_bytes(b"changed after bundle build\n")
        target.chmod(0o444)
        with self.assertRaisesRegex(
            VERIFY.VerificationError, r"changed=\['README\.md'\]"
        ):
            self.verify_fixture_source()

    def test_bundle_and_evidence_permissions_are_private(self) -> None:
        self.assertEqual(stat.S_IMODE(self.fixture.bundle.stat().st_mode), 0o700)
        self.assertTrue(
            all(
                stat.S_IMODE(path.stat().st_mode) == 0o600
                for path in self.fixture.bundle.iterdir()
            )
        )
        (self.fixture.bundle / "source-files.list").chmod(0o644)
        with self.assertRaisesRegex(VERIFY.VerificationError, "mode 0600"):
            self.verify_fixture_archive()


if __name__ == "__main__":
    unittest.main()
