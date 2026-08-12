#!/usr/bin/env python3
"""Pure validation helpers for the production deployment admission wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

DIGEST_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
VCS_REF_RE = re.compile(r"^[0-9a-f]{40}$")
REVISION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PRIVATE_INPUT_BYTES = 1_048_576
MAX_BACKUP_METADATA_BYTES = 16 * 1_048_576
MAX_JSON_INPUT_BYTES = 32 * 1_048_576


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_json(path: Path, label: str) -> Any:
    descriptor = -1
    try:
        descriptor, metadata = open_stable_regular_file(
            path, label, max_size=MAX_JSON_INPUT_BYTES
        )
        content = read_descriptor(descriptor, label, MAX_JSON_INPUT_BYTES)
        assert_stable(descriptor, metadata, label)
        return json.loads(content.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label} {path}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_json(value: Any) -> None:
    json.dump(value, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


def service(config: dict[str, Any], name: str) -> dict[str, Any]:
    services = config.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(name), dict):
        fail(f"resolved Compose config has no {name} service")
    return services[name]


def require_hardened_service(value: dict[str, Any], name: str) -> None:
    if value.get("build") is not None:
        fail(f"production service {name} retains a build definition")
    if value.get("pull_policy") != "never":
        fail(f"production service {name} must use pull_policy never")
    if value.get("read_only") is not True:
        fail(f"production service {name} is not read-only")
    cap_drop = value.get("cap_drop")
    if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
        fail(f"production service {name} does not drop all capabilities")
    security_opt = value.get("security_opt")
    if (
        not isinstance(security_opt, list)
        or "no-new-privileges:true" not in security_opt
    ):
        fail(f"production service {name} lacks no-new-privileges")
    if value.get("privileged") not in (None, False):
        fail(f"production service {name} must not be privileged")
    for key in ("cap_add", "devices", "device_cgroup_rules"):
        if value.get(key) not in (None, []):
            fail(f"production service {name} has prohibited {key}")
    for key in ("network_mode", "pid", "ipc"):
        if value.get(key) not in (None, ""):
            fail(f"production service {name} has prohibited {key}")


def require_command(
    value: dict[str, Any], name: str, expected: list[str] | None
) -> None:
    if value.get("command") != expected or value.get("entrypoint") is not None:
        fail(f"production service {name} has an unexpected command or entrypoint")


def secret_bindings(value: dict[str, Any], name: str) -> dict[str, str]:
    bindings: dict[str, str] = {}
    secrets = value.get("secrets")
    if not isinstance(secrets, list):
        fail(f"production service {name} has no resolved secret bindings")
    for item in secrets:
        if not isinstance(item, dict):
            fail(f"production service {name} has an unresolved secret binding")
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not source or not isinstance(target, str):
            fail(f"production service {name} has an invalid secret binding")
        if target in bindings:
            fail(f"production service {name} has duplicate secret target {target}")
        bindings[target] = source
    return bindings


def require_networks(value: dict[str, Any], name: str, expected: set[str]) -> None:
    networks = value.get("networks")
    if not isinstance(networks, dict) or set(networks) != expected:
        fail(f"production service {name} is not attached to exactly {sorted(expected)}")


def require_no_ports(value: dict[str, Any], name: str) -> None:
    if value.get("ports") not in (None, []):
        fail(f"production service {name} must not publish host ports")


def require_loopback_port(
    value: dict[str, Any], name: str, *, target: int, port_name: str
) -> str:
    ports = value.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        fail(f"production service {name} must publish exactly one port")
    port = ports[0]
    published = port.get("published")
    if isinstance(published, int):
        published = str(published)
    if (
        port.get("name") != port_name
        or port.get("host_ip") != "127.0.0.1"
        or port.get("target") != target
        or port.get("protocol") != "tcp"
        or port.get("mode") != "ingress"
        or not isinstance(published, str)
        or not published.isdigit()
        or not 1 <= int(published) <= 65535
    ):
        fail(f"production service {name} port is not the exact loopback binding")
    return published


def numeric_service_user(value: dict[str, Any], name: str) -> tuple[int, int]:
    user = value.get("user")
    if not isinstance(user, str) or re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
        fail(f"production service {name} must use one explicit numeric UID:GID")
    uid_text, gid_text = user.split(":", 1)
    uid, gid = int(uid_text), int(gid_text)
    if uid == 0 or gid == 0:
        fail(f"production service {name} must not run as root")
    return uid, gid


def repository_regular_file(repo_root: Path, relative: str, label: str) -> Path:
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        fail(f"{label} path is not one normalized repository-relative path")
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve repository root {repo_root}: {exc}")
    current = root
    for index, part in enumerate(candidate.parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            fail(f"cannot inspect {label} {current}: {exc}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} path contains a symbolic link")
        if index < len(candidate.parts) - 1:
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"{label} parent is not a directory")
        elif not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} is not a regular file")
    return current


def signed_sub2api_inputs(
    *,
    versions_lock_path: Path,
    repo_root: Path,
    verified_release: dict[str, Any],
) -> dict[str, str]:
    versions_sha256 = secure_file_sha256(versions_lock_path, "versions lock")
    signed_versions_sha256 = verified_release.get("CONTROL_VERSIONS_LOCK_SHA256")
    release_inputs = verified_release.get("CONTROL_RELEASE_INPUT_SHA256S")
    contract_relative = verified_release.get("CONTROL_SUB2API_AUTH_CONTRACT_PATH")
    signed_contract_sha256 = verified_release.get(
        "CONTROL_SUB2API_AUTH_CONTRACT_SHA256"
    )
    if (
        not isinstance(signed_versions_sha256, str)
        or not SHA256_RE.fullmatch(signed_versions_sha256)
        or versions_sha256 != signed_versions_sha256
    ):
        fail("selected versions lock differs from the signed release input")
    if not isinstance(release_inputs, dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        for path, digest in release_inputs.items()
    ):
        fail("signed release input hash inventory is invalid")
    if release_inputs.get("versions.lock.json") != signed_versions_sha256:
        fail("signed versions lock hash is inconsistent with the release inventory")
    if (
        not isinstance(contract_relative, str)
        or not isinstance(signed_contract_sha256, str)
        or SHA256_RE.fullmatch(signed_contract_sha256) is None
        or release_inputs.get(contract_relative) != signed_contract_sha256
    ):
        fail("signed Sub2API auth contract binding is invalid")

    versions_lock = load_json(versions_lock_path, "versions lock")
    if not isinstance(versions_lock, dict) or versions_lock.get("format_version") != 1:
        fail("versions lock has no supported Sub2API section")
    sub2api = versions_lock.get("sub2api")
    if not isinstance(sub2api, dict):
        fail("versions lock has no supported Sub2API section")
    if sub2api.get("auth_contract_file") != contract_relative:
        fail("versions lock selects a different Sub2API auth contract")
    if sub2api.get("auth_contract_sha256") != signed_contract_sha256:
        fail("versions lock embeds a different Sub2API auth contract hash")

    contract_file = repository_regular_file(
        repo_root, contract_relative, "Sub2API auth contract"
    )
    if (
        secure_file_sha256(contract_file, "Sub2API auth contract")
        != signed_contract_sha256
    ):
        fail("selected Sub2API auth contract differs from the signed release input")
    return {
        "versions_lock_sha256": versions_sha256,
        "auth_contract_file": str(contract_file),
        "auth_contract_relative": contract_relative,
        "auth_contract_sha256": signed_contract_sha256,
    }


def compose_plan(args: argparse.Namespace) -> dict[str, Any]:
    compose_sha256 = secure_file_sha256(args.compose_config, "resolved Compose config")
    config = load_json(args.compose_config, "resolved Compose config")
    if (
        secure_file_sha256(args.compose_config, "resolved Compose config")
        != compose_sha256
    ):
        fail("resolved Compose config changed while it was admitted")
    verified_release = load_json(args.release_verification, "verified release output")
    if not isinstance(config, dict):
        fail("resolved Compose config is not an object")
    if not isinstance(verified_release, dict):
        fail("verified release output is not an object")
    signed_sub2api = signed_sub2api_inputs(
        versions_lock_path=args.versions_lock,
        repo_root=args.repo_root,
        verified_release=verified_release,
    )
    api = service(config, "control-api")
    api_replica = service(config, "control-api-replica")
    migrate = service(config, "control-migrate")
    pwa = service(config, "codex-pwa")
    backup = service(config, "control-backup")
    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
        ("codex-pwa", pwa),
        ("control-backup", backup),
    ):
        require_hardened_service(value, name)

    api_image = api.get("image")
    api_replica_image = api_replica.get("image")
    migrate_image = migrate.get("image")
    pwa_image = pwa.get("image")
    if not isinstance(api_image, str) or not DIGEST_REF_RE.fullmatch(api_image):
        fail("CONTROL_API_IMAGE is not an immutable sha256 digest reference")
    if migrate_image != api_image or api_replica_image != api_image:
        fail("all Control API instances and control-migrate must use one image digest")
    if not isinstance(pwa_image, str) or not DIGEST_REF_RE.fullmatch(pwa_image):
        fail("CONTROL_PWA_IMAGE is not an immutable sha256 digest reference")
    if pwa_image == api_image:
        fail("Control API and PWA unexpectedly use the same image reference")
    backup_image = backup.get("image")
    if not isinstance(backup_image, str) or not DIGEST_REF_RE.fullmatch(backup_image):
        fail("CONTROL_POSTGRES_TOOLS_IMAGE is not an immutable sha256 digest reference")
    api_environment = api.get("environment")
    replica_environment = api_replica.get("environment")
    migrate_environment = migrate.get("environment")
    backup_environment = backup.get("environment")
    if not all(
        isinstance(value, dict)
        for value in (
            api_environment,
            replica_environment,
            migrate_environment,
            backup_environment,
        )
    ):
        fail("Control API environment is missing from resolved Compose config")
    if migrate_environment != api_environment or replica_environment != api_environment:
        fail(
            "Control API instances and control-migrate do not have identical environments"
        )
    if api_environment.get("CONTROL_ENVIRONMENT") != "production":
        fail("CONTROL_ENVIRONMENT must resolve to production")
    if api_environment.get("CONTROL_SUB2API_BASE_URL") != "http://sub2api:8080":
        fail("production Sub2API base URL is not the fixed internal authority")
    if api_environment.get("CONTROL_TRUST_FORWARDED_FOR") != "true":
        fail(
            "production Control API must trust the client IP header overwritten by the "
            "same-host Nginx edge for Sub2API session binding"
        )
    if api_environment.get("CONTROL_REDIS_AUTH_MODE") != "password":
        fail("normal production admission requires the dedicated Redis ACL password")
    database_keys = (
        "CONTROL_DATABASE_PASSWORD_FILE",
        "CONTROL_DB_HOST",
        "CONTROL_DB_PORT",
        "CONTROL_DB_USER",
        "CONTROL_DB_NAME",
    )
    if set(backup_environment) != {"BACKUP_DIR", *database_keys}:
        fail("control-backup has unexpected environment inputs")
    if backup_environment.get("BACKUP_DIR") != "/backups":
        fail("control-backup output path is not the fixed /backups mount")
    for key in database_keys:
        api_value = api_environment.get(key)
        if not isinstance(api_value, str) or not api_value:
            fail(f"production database setting {key} is missing")
        if backup_environment.get(key) != api_value:
            fail(f"control-backup and Control API disagree on {key}")
    if api_environment.get("CONTROL_DATABASE_PASSWORD_FILE") != (
        "/run/secrets/control_db_password"
    ):
        fail("production database password path is not the fixed secret target")
    if api_environment.get("CONTROL_DB_QUERY") not in (None, ""):
        fail("production database query options must be empty for backup equivalence")
    public_origins = api_environment.get("CONTROL_ALLOWED_ORIGINS_CSV")
    if (
        not isinstance(public_origins, str)
        or "," in public_origins
        or not public_origins.startswith("https://")
    ):
        fail("production deployment must have one exact HTTPS public origin")

    release = api_environment.get("CONTROL_BUILD_VERSION")
    source_revision = api_environment.get("CONTROL_BUILD_VCS_REF")
    marker = api_environment.get("CONTROL_SUB2API_CONTRACT_MARKER")
    if (
        not isinstance(release, str)
        or not release
        or release in {"unknown", "replace-me"}
    ):
        fail("CONTROL_RELEASE is not a concrete release identifier")
    if not isinstance(source_revision, str) or not VCS_REF_RE.fullmatch(
        source_revision
    ):
        fail("CONTROL_VCS_REF must be one full 40-character Git commit")
    if not isinstance(marker, str) or marker in {"", "UNVERIFIED"}:
        fail("CONTROL_SUB2API_CONTRACT_MARKER is not admitted")
    verified_values = {
        "CONTROL_API_IMAGE": api_image,
        "CONTROL_PWA_IMAGE": pwa_image,
        "CONTROL_POSTGRES_TOOLS_IMAGE": backup_image,
        "CONTROL_RELEASE": release,
        "CONTROL_VCS_REF": source_revision,
        "CONTROL_SOURCE_REPOSITORY": args.source_repository,
    }
    for key, expected in verified_values.items():
        if verified_release.get(key) != expected:
            fail(
                f"resolved Compose value {key} differs from the signed release verification"
            )
    if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+", args.source_repository):
        fail(
            "externally trusted source repository must be one HTTPS GitHub repository URL"
        )
    signed_migration_head = verified_release.get("CONTROL_MIGRATION_HEAD")
    if not isinstance(signed_migration_head, str) or not REVISION_RE.fullmatch(
        signed_migration_head
    ):
        fail("signed release verification has no valid migration head")

    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
        ("codex-pwa", pwa),
        ("control-backup", backup),
    ):
        labels = value.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.version") != release
        ):
            fail(f"{name} Compose release label does not match CONTROL_RELEASE")

    require_command(api, "control-api", ["api"])
    require_command(api_replica, "control-api-replica", ["api"])
    require_command(migrate, "control-migrate", ["migrate"])
    require_command(pwa, "codex-pwa", None)
    require_command(backup, "control-backup", None)

    application_secrets = {
        "/run/secrets/control_db_password": "control_db_password",
        "/run/secrets/control_redis_password": "control_redis_password",
        "/run/secrets/control_session_hmac_secret": "control_session_hmac_secret",
    }
    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
    ):
        if secret_bindings(value, name) != application_secrets:
            fail(
                f"production service {name} does not have the exact application secrets"
            )
    if secret_bindings(backup, "control-backup") != {
        "/run/secrets/control_db_password": "control_db_password"
    }:
        fail("control-backup does not share exactly the Control database secret")
    if pwa.get("secrets") not in (None, []):
        fail("codex-pwa must not receive application secrets")

    networks = config.get("networks")
    if not isinstance(networks, dict) or not isinstance(
        networks.get("sub2api-network"), dict
    ):
        fail("resolved Compose config has no external Sub2API network")
    external_network = networks["sub2api-network"]
    network_name = external_network.get("name")
    if (
        external_network.get("external") is not True
        or not isinstance(network_name, str)
        or not network_name
    ):
        fail("Sub2API network must be one named external network")
    pwa_network = networks.get("pwa-network")
    expected_pwa_driver_opts = {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    if (
        not isinstance(pwa_network, dict)
        or pwa_network.get("driver") != "bridge"
        or pwa_network.get("internal") not in (None, False)
        or pwa_network.get("enable_ipv6") not in (None, False)
        or pwa_network.get("external") not in (None, False)
        or pwa_network.get("driver_opts") != expected_pwa_driver_opts
        or not isinstance(pwa_network.get("name"), str)
        or not pwa_network["name"]
    ):
        fail(
            "PWA network must be one named non-internal bridge with exact "
            "masquerading-disabled and ICC-disabled options"
        )

    require_networks(api, "control-api", {"sub2api-network"})
    require_networks(api_replica, "control-api-replica", {"sub2api-network"})
    require_networks(migrate, "control-migrate", {"sub2api-network"})
    require_networks(backup, "control-backup", {"sub2api-network"})
    require_networks(pwa, "codex-pwa", {"pwa-network"})
    require_no_ports(migrate, "control-migrate")
    require_no_ports(backup, "control-backup")
    api_port = require_loopback_port(
        api, "control-api", target=8090, port_name="control-api-loopback"
    )
    replica_port = require_loopback_port(
        api_replica,
        "control-api-replica",
        target=8090,
        port_name="control-api-replica-loopback",
    )
    pwa_port = require_loopback_port(
        pwa, "codex-pwa", target=8080, port_name="pwa-loopback"
    )
    if len({api_port, replica_port, pwa_port}) != 3:
        fail("production host port bindings must be distinct")

    volumes = backup.get("volumes")
    backup_sources = [
        volume.get("source")
        for volume in volumes or []
        if isinstance(volume, dict) and volume.get("target") == "/backups"
    ]
    if (
        len(backup_sources) != 1
        or not isinstance(backup_sources[0], str)
        or len(volumes or []) != 1
        or volumes[0].get("type") != "bind"
        or volumes[0].get("read_only") not in (None, False)
    ):
        fail("control-backup must have exactly one /backups bind mount")
    backup_dir = Path(backup_sources[0])
    if not backup_dir.is_absolute():
        fail("resolved backup directory is not absolute")
    backup_uid, backup_gid = numeric_service_user(backup, "control-backup")
    directory_descriptor, _ = open_stable_directory(
        backup_dir,
        "production backup directory",
        expected_uid=backup_uid,
        exact_mode=0o700,
    )
    os.close(directory_descriptor)
    repo_root = args.repo_root.resolve()
    try:
        backup_dir.resolve(strict=False).relative_to(repo_root)
    except ValueError:
        pass
    else:
        fail("production backup directory must be outside the source checkout")

    project_name = config.get("name")
    if (
        not isinstance(project_name, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name) is None
    ):
        fail("resolved Compose project name is invalid")

    return {
        "format_version": 1,
        "compose_project": project_name,
        "resolved_compose_sha256": compose_sha256,
        "api_image": api_image,
        "pwa_image": pwa_image,
        "backup_image": backup_image,
        "backup_directory": str(backup_dir),
        "backup_owner_uid": backup_uid,
        "backup_owner_gid": backup_gid,
        "release": release,
        "source_revision": source_revision,
        "source_repository": args.source_repository,
        "signed_migration_head": signed_migration_head,
        "sub2api_contract_marker": marker,
        **signed_sub2api,
        "sub2api_network": network_name,
        "pwa_network": pwa_network["name"],
        "pwa_network_driver": "bridge",
        "pwa_network_driver_opts": expected_pwa_driver_opts,
        "public_origin": public_origins,
        "instances": {
            "control-api": {
                "image_id_key": "api",
                "network": network_name,
                "target_port": 8090,
                "published_port": api_port,
            },
            "control-api-replica": {
                "image_id_key": "api",
                "network": network_name,
                "target_port": 8090,
                "published_port": replica_port,
            },
            "codex-pwa": {
                "image_id_key": "pwa",
                "network": pwa_network["name"],
                "target_port": 8080,
                "published_port": pwa_port,
            },
        },
    }


def inspect_object(path: Path, label: str) -> dict[str, Any]:
    value = load_json(path, label)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} must contain exactly one image inspect object")
    return value[0]


def image_evidence(
    image: dict[str, Any],
    *,
    reference: str,
    release: str,
    source_revision: str,
    source_repository: str,
    label: str,
) -> dict[str, Any]:
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        fail(f"{label} image has no full sha256 image ID")
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or reference not in repo_digests:
        fail(f"{label} image RepoDigests do not contain the exact configured reference")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        fail(f"{label} image has no OCI labels")
    expected_labels = {
        "org.opencontainers.image.version": release,
        "org.opencontainers.image.revision": source_revision,
        "org.opencontainers.image.source": source_repository,
    }
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            fail(f"{label} image OCI label {key} mismatch")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        fail(f"{label} image platform must be exactly linux/amd64")
    return {
        "reference": reference,
        "image_id": image_id,
        "created": image.get("Created"),
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
        "oci_labels": expected_labels,
    }


def release_images(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "deployment plan")
    if not isinstance(plan, dict):
        fail("deployment plan is not an object")
    api = image_evidence(
        inspect_object(args.api_inspect, "Control API image inspect"),
        reference=plan["api_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="Control API",
    )
    pwa = image_evidence(
        inspect_object(args.pwa_inspect, "PWA image inspect"),
        reference=plan["pwa_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="PWA",
    )
    if api["image_id"] == pwa["image_id"]:
        fail("Control API and PWA resolve to the same image ID")
    backup_tools = image_evidence(
        inspect_object(args.backup_inspect, "backup tools image inspect"),
        reference=plan["backup_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="backup tools",
    )
    if len({api["image_id"], pwa["image_id"], backup_tools["image_id"]}) != 3:
        fail("release components must resolve to three distinct image IDs")
    return {
        "format_version": 1,
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "api": api,
        "pwa": pwa,
        "backup_tools": backup_tools,
    }


def metadata_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def open_stable_regular_file(
    path: Path,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
    max_size: int | None = None,
) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {label} {path}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        fail(f"{label} is not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
        if max_size is not None and opened_metadata.st_size > max_size:
            fail(f"{label} is larger than {max_size} bytes")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def open_stable_regular_file_at(
    directory_descriptor: int,
    name: str,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
    max_size: int | None = None,
) -> tuple[int, os.stat_result]:
    if name in {"", ".", ".."} or "/" in name:
        fail(f"{label} has an invalid relative name")
    try:
        path_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        fail(f"cannot stat {label}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        fail(f"{label} is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
        if max_size is not None and opened_metadata.st_size > max_size:
            fail(f"{label} is larger than {max_size} bytes")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def open_stable_directory(
    path: Path,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {label} {path}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(path_metadata.st_mode):
        fail(f"{label} is not a real directory: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def assert_stable(descriptor: int, initial: os.stat_result, label: str) -> None:
    if metadata_signature(os.fstat(descriptor)) != metadata_signature(initial):
        fail(f"{label} changed while it was being verified")


def read_descriptor(descriptor: int, label: str, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= maximum:
        chunk = os.read(descriptor, min(131_072, maximum + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > maximum:
        fail(f"{label} is larger than {maximum} bytes")
    return bytes(content)


def hash_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1_048_576):
        digest.update(chunk)
    return digest.hexdigest()


def secure_file_sha256(path: Path, label: str) -> str:
    descriptor, metadata = open_stable_regular_file(path, label)
    try:
        digest = hash_descriptor(descriptor)
        assert_stable(descriptor, metadata, label)
        return digest
    finally:
        os.close(descriptor)


def secure_text_file(
    path: Path, label: str, maximum: int = MAX_PRIVATE_INPUT_BYTES
) -> str:
    descriptor, metadata = open_stable_regular_file(path, label, max_size=maximum)
    try:
        content = read_descriptor(descriptor, label, maximum)
        assert_stable(descriptor, metadata, label)
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {exc}")
    finally:
        os.close(descriptor)


def regular_private_file(path: Path, label: str) -> os.stat_result:
    descriptor, metadata = open_stable_regular_file(path, label, exact_mode=0o600)
    os.close(descriptor)
    return metadata


def read_private_opaque_file(path: Path, label: str) -> str:
    descriptor, opened_metadata = open_stable_regular_file(
        path,
        label,
        expected_uid=os.geteuid(),
        exact_mode=0o600,
        max_size=65_536,
    )
    try:
        content = read_descriptor(descriptor, label, 65_536)
        assert_stable(descriptor, opened_metadata, label)
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    finally:
        os.close(descriptor)

    try:
        value = content.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {exc}")
    if not value or any(character.isspace() for character in value):
        fail(f"{label} must contain one opaque value")
    return value


def operator_directory(args: argparse.Namespace) -> dict[str, Any]:
    if not args.directory.is_absolute():
        fail("operator directory must be absolute")
    descriptor, metadata = open_stable_directory(
        args.directory,
        args.label,
        expected_uid=os.geteuid(),
        exact_mode=0o700,
    )
    os.close(descriptor)
    return {
        "format_version": 1,
        "path": str(args.directory),
        "owner_uid": metadata.st_uid,
        "mode": "0700",
    }


def copy_to_private_destination(
    args: argparse.Namespace,
    *,
    exact_source_mode: int | None,
    forbidden_source_mode: int,
    expected_sha256: str | None,
    require_single_link: bool,
) -> dict[str, Any]:
    if not args.source.is_absolute() or not args.destination.is_absolute():
        fail("private input source and destination must be absolute")
    source_descriptor, source_metadata = open_stable_regular_file(
        args.source,
        args.label,
        expected_uid=os.geteuid(),
        exact_mode=exact_source_mode,
        max_size=args.max_bytes,
    )
    destination_parent_descriptor = -1
    destination_descriptor = -1
    created = False
    copy_succeeded = False
    try:
        if require_single_link and source_metadata.st_nlink != 1:
            fail(f"{args.label} must have exactly one hard link")
        if stat.S_IMODE(source_metadata.st_mode) & forbidden_source_mode:
            fail(f"{args.label} is writable by an untrusted group or user")
        content = read_descriptor(source_descriptor, args.label, args.max_bytes)
        if not content or b"\x00" in content:
            fail(f"{args.label} is empty or contains NUL bytes")
        assert_stable(source_descriptor, source_metadata, args.label)
        source_sha256 = hashlib.sha256(content).hexdigest()
        if expected_sha256 is not None and source_sha256 != expected_sha256:
            fail(f"{args.label} differs from its admitted SHA-256")
        destination_parent_descriptor, _ = open_stable_directory(
            args.destination.parent,
            "private input destination directory",
            expected_uid=os.geteuid(),
            exact_mode=0o700,
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_descriptor = os.open(
            args.destination.name,
            flags,
            0o600,
            dir_fd=destination_parent_descriptor,
        )
        created = True
        view = memoryview(content)
        while view:
            written = os.write(destination_descriptor, view)
            if written <= 0:
                fail(f"could not write private copy of {args.label}")
            view = view[written:]
        os.fsync(destination_descriptor)
        os.fsync(destination_parent_descriptor)
        assert_stable(source_descriptor, source_metadata, args.label)
        copy_succeeded = True
    except OSError as exc:
        fail(f"cannot securely copy {args.label}: {exc}")
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if created and not copy_succeeded:
            try:
                os.unlink(args.destination.name, dir_fd=destination_parent_descriptor)
            except OSError:
                pass
        if destination_parent_descriptor >= 0:
            os.close(destination_parent_descriptor)
        os.close(source_descriptor)
    return {
        "format_version": 1,
        "source_sha256": source_sha256,
        "size": len(content),
        "destination": str(args.destination),
    }


def copy_private_file(args: argparse.Namespace) -> dict[str, Any]:
    return copy_to_private_destination(
        args,
        exact_source_mode=0o600,
        forbidden_source_mode=0,
        expected_sha256=None,
        require_single_link=False,
    )


def copy_admitted_file(args: argparse.Namespace) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(args.expected_sha256):
        fail("admitted file SHA-256 must be 64 lowercase hexadecimal characters")
    return copy_to_private_destination(
        args,
        exact_source_mode=None,
        forbidden_source_mode=0o022,
        expected_sha256=args.expected_sha256,
        require_single_link=True,
    )


def backup_evidence(args: argparse.Namespace) -> dict[str, Any]:
    directory = args.directory
    if not directory.is_absolute():
        fail("backup directory must be absolute")
    directory_descriptor, directory_metadata = open_stable_directory(
        directory,
        "backup directory",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o700,
    )
    descriptors: list[int] = []
    try:
        now = datetime.now(UTC).timestamp()
        candidates: list[tuple[str, int, os.stat_result]] = []
        for name in os.listdir(directory_descriptor):
            if re.fullmatch(r"codex-control-[0-9A-Za-zT_-]+\.dump", name) is None:
                continue
            path = directory / name
            descriptor, metadata = open_stable_regular_file_at(
                directory_descriptor,
                name,
                f"backup dump {path}",
                expected_uid=args.expected_owner_uid,
                exact_mode=0o600,
            )
            descriptors.append(descriptor)
            if metadata.st_mtime >= args.not_before:
                candidates.append((name, descriptor, metadata))
        if len(candidates) != 1:
            fail(f"expected exactly one new backup dump, observed {len(candidates)}")
        dump_name, dump_descriptor, dump_metadata = candidates[0]
        dump = directory / dump_name
        if dump_metadata.st_mtime > now + 60:
            fail("backup dump modification time is in the future")
        if now - dump_metadata.st_mtime > args.max_age_seconds:
            fail("backup dump is stale")

        stem = dump_name.removesuffix(".dump")
        manifest_name = f"{stem}.contents.txt"
        checksum_name = f"{stem}.sha256"
        manifest = directory / manifest_name
        checksum = directory / checksum_name
        manifest_descriptor, manifest_metadata = open_stable_regular_file_at(
            directory_descriptor,
            manifest_name,
            "backup manifest",
            expected_uid=args.expected_owner_uid,
            exact_mode=0o600,
            max_size=MAX_BACKUP_METADATA_BYTES,
        )
        descriptors.append(manifest_descriptor)
        checksum_descriptor, checksum_metadata = open_stable_regular_file_at(
            directory_descriptor,
            checksum_name,
            "backup checksum",
            expected_uid=args.expected_owner_uid,
            exact_mode=0o600,
            max_size=1024,
        )
        descriptors.append(checksum_descriptor)
        for label, metadata in (
            ("manifest", manifest_metadata),
            ("checksum", checksum_metadata),
        ):
            if metadata.st_mtime < args.not_before or metadata.st_mtime > now + 60:
                fail(f"backup {label} was not created in this admission window")

        try:
            checksum_lines = (
                read_descriptor(checksum_descriptor, "backup checksum", 1024)
                .decode("ascii")
                .splitlines()
            )
        except UnicodeDecodeError as exc:
            fail(f"backup checksum is not ASCII: {exc}")
        if len(checksum_lines) != 1:
            fail("backup checksum file must contain exactly one line")
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\s]+)", checksum_lines[0])
        if match is None or match.group(2) != dump_name:
            fail("backup checksum line has an invalid digest or filename")
        observed_sha256 = hash_descriptor(dump_descriptor)
        if observed_sha256 != match.group(1):
            fail("backup dump checksum mismatch")

        descriptor_root = (
            Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
        )
        os.lseek(dump_descriptor, 0, os.SEEK_SET)
        with tempfile.TemporaryFile() as error_output:
            try:
                process = subprocess.Popen(
                    [
                        str(args.pg_restore),
                        "--list",
                        str(descriptor_root / str(dump_descriptor)),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=error_output,
                    pass_fds=(dump_descriptor,),
                )
            except OSError as exc:
                fail(f"pg_restore could not start: {exc}")
            assert process.stdout is not None
            recreated_manifest = bytearray()
            while len(recreated_manifest) <= MAX_BACKUP_METADATA_BYTES:
                chunk = process.stdout.read(
                    min(
                        131_072,
                        MAX_BACKUP_METADATA_BYTES + 1 - len(recreated_manifest),
                    )
                )
                if not chunk:
                    break
                recreated_manifest.extend(chunk)
            if len(recreated_manifest) > MAX_BACKUP_METADATA_BYTES:
                process.kill()
                process.wait()
                fail("pg_restore manifest exceeds the admission size limit")
            return_code = process.wait()
            if return_code != 0:
                error_output.seek(0)
                error_text = error_output.read(4096).decode("utf-8", errors="replace")
                fail(f"pg_restore could not parse the new backup: {error_text.strip()}")

        stored_manifest = read_descriptor(
            manifest_descriptor, "backup manifest", MAX_BACKUP_METADATA_BYTES
        )
        if not stored_manifest or bytes(recreated_manifest) != stored_manifest:
            fail("stored backup manifest differs from pg_restore --list output")

        for descriptor, metadata, label in (
            (dump_descriptor, dump_metadata, "backup dump"),
            (manifest_descriptor, manifest_metadata, "backup manifest"),
            (checksum_descriptor, checksum_metadata, "backup checksum"),
        ):
            assert_stable(descriptor, metadata, label)
        assert_stable(directory_descriptor, directory_metadata, "backup directory")

        return {
            "format_version": 1,
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "dump_path": str(dump),
            "dump_sha256": observed_sha256,
            "dump_size": dump_metadata.st_size,
            "dump_mtime": datetime.fromtimestamp(dump_metadata.st_mtime, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "manifest_path": str(manifest),
            "manifest_sha256": hashlib.sha256(stored_manifest).hexdigest(),
            "checksum_path": str(checksum),
            "owner_uid": args.expected_owner_uid,
        }
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(directory_descriptor)


def normalize_revision(value: str, label: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    candidates: list[str] = []
    for line in lines:
        token = line.split(maxsplit=1)[0]
        if REVISION_RE.fullmatch(token):
            candidates.append(token)
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) != 1:
        fail(f"{label} did not contain exactly one migration revision")
    return candidates[0]


def revisions(args: argparse.Namespace) -> dict[str, Any]:
    current = normalize_revision(
        secure_text_file(args.current, "alembic current"), "alembic current"
    )
    head = normalize_revision(
        secure_text_file(args.head, "alembic heads"), "alembic heads"
    )
    if args.plan is not None:
        plan = load_json(args.plan, "deployment plan")
        if not isinstance(plan, dict) or plan.get("signed_migration_head") != head:
            fail("packaged Alembic head differs from the signed release migration head")
    if args.require_current_head and current != head:
        fail("database revision does not match the admitted migration head")
    return {"source_database_revision": current, "target_migration_head": head}


def deployment_record(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "deployment plan")
    releases = load_json(args.releases, "release image evidence")
    sub2api = load_json(args.sub2api, "Sub2API attestation")
    backup = load_json(args.backup, "backup evidence")
    revisions_value = load_json(args.revisions, "migration revision evidence")
    signed_release = load_json(args.release_verification, "signed release verification")
    smoke_input_value = load_json(args.smoke_input, "production smoke input evidence")
    for label, value in (
        ("deployment plan", plan),
        ("release image evidence", releases),
        ("Sub2API attestation", sub2api),
        ("backup evidence", backup),
        ("migration revision evidence", revisions_value),
        ("signed release verification", signed_release),
        ("production smoke input evidence", smoke_input_value),
    ):
        if not isinstance(value, dict):
            fail(f"{label} is not an object")
    resolved_compose_sha256 = secure_file_sha256(
        args.compose_config, "resolved Compose config"
    )
    if plan.get("resolved_compose_sha256") != resolved_compose_sha256:
        fail("resolved Compose snapshot changed after admission")
    record = {
        "format_version": 1,
        "status": args.status,
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "release": plan["release"],
        "release_source_revision": plan["source_revision"],
        "source_database_revision": revisions_value["source_database_revision"],
        "target_migration_head": revisions_value["target_migration_head"],
        "signed_release": {
            "values": signed_release,
            "sha256": secure_file_sha256(
                args.release_verification, "signed release verification"
            ),
        },
        "resolved_compose_sha256": resolved_compose_sha256,
        "production_smoke_input": smoke_input_value,
        "images": releases,
        "sub2api": sub2api,
        "backup": backup,
    }
    if args.status == "deployed":
        if args.running is None or args.smoke is None or args.deployed_revision is None:
            fail(
                "deployed record requires running, smoke, and deployed revision evidence"
            )
        running = load_json(args.running, "running container evidence")
        deployed_revision = normalize_revision(
            secure_text_file(args.deployed_revision, "deployed alembic current"),
            "deployed alembic current",
        )
        if deployed_revision != revisions_value["target_migration_head"]:
            fail(
                "deployed database revision does not match the admitted migration head"
            )
        smoke_metadata = regular_private_file(args.smoke, "production smoke output")
        if smoke_metadata.st_size == 0:
            fail("production smoke output is empty")
        record["deployed_database_revision"] = deployed_revision
        record["running"] = running
        record["smoke"] = {
            "path": str(args.smoke),
            "sha256": secure_file_sha256(args.smoke, "production smoke output"),
            "size": smoke_metadata.st_size,
        }
    return record


def runtime_match(args: argparse.Namespace) -> dict[str, Any]:
    first = load_json(args.first, "first Sub2API attestation")
    second = load_json(args.second, "second Sub2API attestation")
    plan = load_json(args.plan, "deployment plan")
    if (
        not isinstance(first, dict)
        or not isinstance(second, dict)
        or not isinstance(plan, dict)
    ):
        fail("runtime comparison inputs must be objects")
    identity_fields = (
        "container_id",
        "image_id",
        "image_digest",
        "binary_sha256",
        "runtime_version",
        "runtime_commit",
        "runtime_built_at",
        "contract_sha256",
        "network",
        "network_alias",
    )
    for field in identity_fields:
        if first.get(field) != second.get(field):
            fail(f"Sub2API runtime changed during admission: {field}")
    expected_marker = f"{second['runtime_version']}/{second['runtime_commit'][:7]}"
    if plan.get("sub2api_contract_marker") != expected_marker:
        fail("resolved CONTROL_SUB2API_CONTRACT_MARKER does not match the runtime")
    if second.get("auth_evidence") is None:
        fail("final Sub2API attestation has no authentication evidence")
    return {
        "format_version": 1,
        "matched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "container_id": second["container_id"],
        "image_id": second["image_id"],
        "contract_marker": expected_marker,
    }


def require_pwa_network_inspect(
    path: Path,
    *,
    expected_name: str,
    expected_project: str,
    pwa_container: dict[str, Any],
) -> dict[str, Any]:
    regular_private_file(path, "PWA Docker network inspection")
    value = load_json(path, "PWA Docker network inspection")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail("PWA Docker network inspection must contain exactly one object")
    network = value[0]
    expected_options = {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    network_id = network.get("Id")
    labels = network.get("Labels")
    if (
        not isinstance(network_id, str)
        or not CONTAINER_ID_RE.fullmatch(network_id)
        or network.get("Name") != expected_name
        or network.get("Driver") != "bridge"
        or network.get("Scope") != "local"
        or network.get("Internal") is not False
        or network.get("Attachable") is not False
        or network.get("Ingress") is not False
        or network.get("ConfigOnly") is not False
        or network.get("EnableIPv6") is not False
        or network.get("Options") != expected_options
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != expected_project
        or labels.get("com.docker.compose.network") != "pwa-network"
    ):
        fail("running PWA network does not retain the admitted bridge boundary")
    container_id = pwa_container.get("Id")
    container_name = pwa_container.get("Name")
    network_settings = pwa_container.get("NetworkSettings")
    attachments = (
        network_settings.get("Networks") if isinstance(network_settings, dict) else None
    )
    attachment = (
        attachments.get(expected_name) if isinstance(attachments, dict) else None
    )
    if (
        not isinstance(container_id, str)
        or not CONTAINER_ID_RE.fullmatch(container_id)
        or not isinstance(container_name, str)
        or not container_name.startswith("/")
        or not isinstance(attachment, dict)
        or attachment.get("NetworkID") != network_id
        or not isinstance(attachment.get("EndpointID"), str)
        or not CONTAINER_ID_RE.fullmatch(attachment["EndpointID"])
    ):
        fail("running PWA container is not bound to the inspected network identity")
    containers = network.get("Containers")
    if not isinstance(containers, dict) or set(containers) != {container_id}:
        fail("running PWA network must contain exactly the admitted PWA container")
    member = containers[container_id]
    if (
        not isinstance(member, dict)
        or member.get("Name") != container_name.removeprefix("/")
        or member.get("EndpointID") != attachment["EndpointID"]
    ):
        fail("running PWA network has inconsistent container attachment evidence")
    return {
        "network_id": network_id,
        "name": expected_name,
        "compose_project": expected_project,
        "driver": "bridge",
        "internal": False,
        "enable_ipv6": False,
        "options": expected_options,
        "container_id": container_id,
    }


def running_containers(args: argparse.Namespace) -> dict[str, Any]:
    releases = load_json(args.releases, "release image evidence")
    plan = load_json(args.plan, "deployment plan")
    if not isinstance(releases, dict) or not isinstance(plan, dict):
        fail("running container evidence inputs must be objects")
    expected_instances = plan.get("instances")
    if not isinstance(expected_instances, dict):
        fail("deployment plan has no admitted instance set")
    result: dict[str, Any] = {"format_version": 1, "containers": {}}
    observed_containers: dict[str, dict[str, Any]] = {}
    observed_ids: set[str] = set()
    for label, path in (
        ("control-api", args.api_inspect),
        ("control-api-replica", args.api_replica_inspect),
        ("codex-pwa", args.pwa_inspect),
    ):
        container = inspect_object(path, f"{label} container inspect")
        expected = expected_instances.get(label)
        if not isinstance(expected, dict):
            fail(f"deployment plan has no admitted {label} instance")
        release_key = expected.get("image_id_key")
        if release_key not in {"api", "pwa"}:
            fail(f"deployment plan has invalid image binding for {label}")
        expected_image_id = releases[release_key]["image_id"]
        if container.get("Image") != expected_image_id:
            fail(f"running {label} does not use the admitted image ID")
        container_id = container.get("Id")
        if not isinstance(container_id, str) or not CONTAINER_ID_RE.fullmatch(
            container_id
        ):
            fail(f"running {label} has no full Docker container ID")
        if container_id in observed_ids:
            fail("two admitted services unexpectedly resolve to one container")
        observed_ids.add(container_id)
        observed_containers[label] = container
        host_config = container.get("HostConfig")
        if (
            not isinstance(host_config, dict)
            or host_config.get("ReadonlyRootfs") is not True
        ):
            fail(f"running {label} root filesystem is not read-only")
        if host_config.get("Privileged") not in (None, False) or host_config.get(
            "CapAdd"
        ) not in (None, []):
            fail(f"running {label} has elevated host privileges")
        target_port = expected.get("target_port")
        published_port = expected.get("published_port")
        expected_bindings = {
            f"{target_port}/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": str(published_port)}
            ]
        }
        if host_config.get("PortBindings") != expected_bindings:
            fail(f"running {label} does not have the admitted loopback port binding")
        state = container.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            fail(f"running {label} is stopped")
        health = state.get("Health")
        if not isinstance(health, dict) or health.get("Status") != "healthy":
            fail(f"running {label} is not healthy")
        network_settings = container.get("NetworkSettings")
        attached_networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        if not isinstance(attached_networks, dict) or set(attached_networks) != {
            expected.get("network")
        }:
            fail(f"running {label} is not on exactly the admitted network")
        runtime_ports = network_settings.get("Ports")
        expected_runtime_port = [
            {"HostIp": "127.0.0.1", "HostPort": str(published_port)}
        ]
        if (
            not isinstance(runtime_ports, dict)
            or runtime_ports.get(f"{target_port}/tcp") != expected_runtime_port
            or any(
                value not in (None, [])
                for key, value in runtime_ports.items()
                if key != f"{target_port}/tcp"
            )
        ):
            fail(f"running {label} does not expose exactly the admitted runtime port")
        result["containers"][label] = {
            "container_id": container_id,
            "image_id": expected_image_id,
            "health": "healthy",
            "network": expected["network"],
            "published_port": str(published_port),
        }
    pwa_instance = result["containers"].get("codex-pwa")
    pwa_network_name = plan.get("pwa_network")
    if not isinstance(pwa_instance, dict) or not isinstance(pwa_network_name, str):
        fail("deployment plan has no admitted PWA network instance")
    compose_project = plan.get("compose_project")
    if not isinstance(compose_project, str) or not compose_project:
        fail("deployment plan has no admitted Compose project")
    result["pwa_network"] = require_pwa_network_inspect(
        args.pwa_network_inspect,
        expected_name=pwa_network_name,
        expected_project=compose_project,
        pwa_container=observed_containers["codex-pwa"],
    )
    result["verified_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return result


def smoke_input(args: argparse.Namespace) -> dict[str, Any]:
    if not args.token_file.is_absolute():
        fail("production smoke access-token file must be absolute")
    token = read_private_opaque_file(
        args.token_file, "production smoke access-token file"
    )
    if (
        not args.expected_user_id
        or len(args.expected_user_id) > 256
        or any(
            character.isspace() or ord(character) < 32
            for character in args.expected_user_id
        )
    ):
        fail("production smoke expected user ID must be one opaque identifier")
    return {
        "format_version": 1,
        "access_token_file_validated": True,
        "access_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "expected_user_id": args.expected_user_id,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    compose_parser = commands.add_parser("compose-plan")
    compose_parser.add_argument("--compose-config", type=Path, required=True)
    compose_parser.add_argument("--release-verification", type=Path, required=True)
    compose_parser.add_argument("--versions-lock", type=Path, required=True)
    compose_parser.add_argument("--source-repository", required=True)
    compose_parser.add_argument("--repo-root", type=Path, required=True)
    compose_parser.set_defaults(handler=compose_plan)

    images_parser = commands.add_parser("release-images")
    images_parser.add_argument("--plan", type=Path, required=True)
    images_parser.add_argument("--api-inspect", type=Path, required=True)
    images_parser.add_argument("--pwa-inspect", type=Path, required=True)
    images_parser.add_argument("--backup-inspect", type=Path, required=True)
    images_parser.set_defaults(handler=release_images)

    backup_parser = commands.add_parser("backup")
    backup_parser.add_argument("--directory", type=Path, required=True)
    backup_parser.add_argument("--not-before", type=float, required=True)
    backup_parser.add_argument("--max-age-seconds", type=int, default=600)
    backup_parser.add_argument("--pg-restore", type=Path, default=Path("pg_restore"))
    backup_parser.add_argument("--expected-owner-uid", type=int, required=True)
    backup_parser.set_defaults(handler=backup_evidence)

    revisions_parser = commands.add_parser("revisions")
    revisions_parser.add_argument("--current", type=Path, required=True)
    revisions_parser.add_argument("--head", type=Path, required=True)
    revisions_parser.add_argument("--plan", type=Path)
    revisions_parser.add_argument("--require-current-head", action="store_true")
    revisions_parser.set_defaults(handler=revisions)

    record_parser = commands.add_parser("record")
    record_parser.add_argument("--plan", type=Path, required=True)
    record_parser.add_argument("--releases", type=Path, required=True)
    record_parser.add_argument("--sub2api", type=Path, required=True)
    record_parser.add_argument("--backup", type=Path, required=True)
    record_parser.add_argument("--revisions", type=Path, required=True)
    record_parser.add_argument("--release-verification", type=Path, required=True)
    record_parser.add_argument("--compose-config", type=Path, required=True)
    record_parser.add_argument("--smoke-input", type=Path, required=True)
    record_parser.add_argument(
        "--status", choices=("admitted_for_migration", "deployed"), required=True
    )
    record_parser.add_argument("--running", type=Path)
    record_parser.add_argument("--smoke", type=Path)
    record_parser.add_argument("--deployed-revision", type=Path)
    record_parser.set_defaults(handler=deployment_record)

    runtime_match_parser = commands.add_parser("runtime-match")
    runtime_match_parser.add_argument("--first", type=Path, required=True)
    runtime_match_parser.add_argument("--second", type=Path, required=True)
    runtime_match_parser.add_argument("--plan", type=Path, required=True)
    runtime_match_parser.set_defaults(handler=runtime_match)

    running_parser = commands.add_parser("running-containers")
    running_parser.add_argument("--releases", type=Path, required=True)
    running_parser.add_argument("--plan", type=Path, required=True)
    running_parser.add_argument("--api-inspect", type=Path, required=True)
    running_parser.add_argument("--api-replica-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-network-inspect", type=Path, required=True)
    running_parser.set_defaults(handler=running_containers)

    smoke_input_parser = commands.add_parser("smoke-input")
    smoke_input_parser.add_argument("--token-file", type=Path, required=True)
    smoke_input_parser.add_argument("--expected-user-id", required=True)
    smoke_input_parser.set_defaults(handler=smoke_input)

    directory_parser = commands.add_parser("operator-directory")
    directory_parser.add_argument("--directory", type=Path, required=True)
    directory_parser.add_argument("--label", required=True)
    directory_parser.set_defaults(handler=operator_directory)

    copy_parser = commands.add_parser("copy-private-file")
    copy_parser.add_argument("--source", type=Path, required=True)
    copy_parser.add_argument("--destination", type=Path, required=True)
    copy_parser.add_argument("--label", required=True)
    copy_parser.add_argument("--max-bytes", type=int, default=MAX_PRIVATE_INPUT_BYTES)
    copy_parser.set_defaults(handler=copy_private_file)

    admitted_copy_parser = commands.add_parser("copy-admitted-file")
    admitted_copy_parser.add_argument("--source", type=Path, required=True)
    admitted_copy_parser.add_argument("--destination", type=Path, required=True)
    admitted_copy_parser.add_argument("--label", required=True)
    admitted_copy_parser.add_argument("--expected-sha256", required=True)
    admitted_copy_parser.add_argument(
        "--max-bytes", type=int, default=MAX_PRIVATE_INPUT_BYTES
    )
    admitted_copy_parser.set_defaults(handler=copy_admitted_file)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        write_json(args.handler(args))
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"deployment-admission: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
