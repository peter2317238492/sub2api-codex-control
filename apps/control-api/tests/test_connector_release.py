from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from conftest import Harness, exchange
from pydantic import ValidationError

from control_api.app import create_app
from control_api.config import Settings
from control_api.connector_release import (
    admitted_connector_release,
    connector_release_metadata_sha256,
)
from control_api.schemas import ConnectorReleaseMetadata

REPOSITORY = "https://github.com/peter2317238492/sub2api-codex-control"
VERSION = "0.1.6"
TAG = f"connector-v{VERSION}"


def release_metadata() -> dict[str, Any]:
    assets = []
    for index, (os_name, arch, package_format) in enumerate(
        (
            ("linux", "amd64", "deb"),
            ("linux", "amd64", "rpm"),
            ("linux", "arm64", "deb"),
            ("linux", "arm64", "rpm"),
        ),
        start=1,
    ):
        filename = f"sub2api-codex-connector_{VERSION}_{os_name}_{arch}.{package_format}"
        assets.append(
            {
                "os": os_name,
                "arch": arch,
                "package_format": package_format,
                "filename": filename,
                "download_url": f"{REPOSITORY}/releases/download/{TAG}/{filename}",
                "sha256": f"{index:064x}",
                "size": 1000 + index,
                "signature_bundle": f"{filename}.sigstore.json",
                "sbom": {
                    "format": "SPDX-2.3-json",
                    "filename": f"{filename}.spdx.json",
                    "sha256": f"{index + 10:064x}",
                    "size": 2000 + index,
                    "signature_bundle": f"{filename}.spdx.json.sigstore.json",
                },
                "provenance": {
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "filename": f"{filename}.intoto.json",
                    "sha256": f"{index + 20:064x}",
                    "size": 3000 + index,
                    "signature_bundle": f"{filename}.intoto.json.sigstore.json",
                    "attestation_bundle": f"{filename}.intoto.sigstore.json",
                },
            }
        )
    return {
        "format_version": 1,
        "release_mode": "release",
        "releasable": True,
        "source_repository": REPOSITORY,
        "source_commit": "a" * 40,
        "version": VERSION,
        "tag": TAG,
        "codex_version": "0.147.0",
        "schema_digest": "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b",
        "manifest": {
            "filename": "manifest.json",
            "sha256": "b" * 64,
            "size": 4000,
            "signature_bundle": "manifest.json.sigstore.json",
        },
        "config_path_hint": "~/.config/sub2api-codex-connector/connector.json",
        "pair_command": "sub2api-codex-connector-ctl pair",
        "start_command": "sub2api-codex-connector-ctl start",
        "assets": assets,
    }


def production_settings(connector_release_metadata_json: str) -> Settings:
    return Settings(
        environment="production",
        database_url="postgresql+asyncpg://control:secret@postgres/control",
        redis_url="redis://redis:6379/0",
        session_hmac_secret="3f" * 32,
        metrics_bearer_token="4e" * 32,
        cookie_secure=True,
        allowed_origins_csv="https://control.example.test",
        sub2api_contract_marker="0.1.178/e0c48a1",
        connector_release_metadata_json=connector_release_metadata_json,
    )


def test_release_metadata_requires_the_fixed_complete_native_inventory() -> None:
    metadata = ConnectorReleaseMetadata.model_validate(release_metadata())
    assert metadata.tag == TAG
    assert len(metadata.assets) == 4

    for mutate in (
        lambda value: value.update(format_version=True),
        lambda value: value.update(releasable=False),
        lambda value: value.update(releasable=1),
        lambda value: value.update(source_repository="https://github.com/example/control"),
        lambda value: value.update(source_commit="A" * 40),
        lambda value: value.update(tag="connector-v0.1.0-rc.1"),
        lambda value: value["manifest"].update(filename="manifest-latest.json"),
        lambda value: value["assets"].pop(),
        lambda value: value["assets"][0].update(
            download_url=f"{REPOSITORY}/releases/latest/download/connector.deb"
        ),
        lambda value: value["assets"][0].update(filename="connector.deb"),
        lambda value: value["assets"][0].update(sha256="A" * 64),
        lambda value: value["assets"][0].update(size="1001"),
        lambda value: value["assets"][0]["sbom"].update(
            filename="connector.spdx.json"
        ),
        lambda value: value["assets"][0]["provenance"].update(
            predicate_type="https://slsa.dev/provenance/v0.2"
        ),
        lambda value: value["assets"][0]["provenance"].update(
            attestation_bundle="connector.intoto.sigstore.json"
        ),
        lambda value: value.update(untrusted="extra"),
    ):
        invalid = copy.deepcopy(release_metadata())
        mutate(invalid)
        with pytest.raises(ValidationError):
            ConnectorReleaseMetadata.model_validate(invalid)


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "x" * (16 * 1024 + 1),
        "[" * 1200 + "0" + "]" * 1200,
        '{"release_mode":"release","release_mode":"release"}',
        json.dumps({**release_metadata(), "version": "0.1.7", "tag": "connector-v0.1.7"}),
        json.dumps({**release_metadata(), "codex_version": "0.148.0"}),
        json.dumps({**release_metadata(), "schema_digest": "0" * 64}),
    ],
)
def test_release_loader_returns_null_for_untrusted_or_incompatible_metadata(raw: str) -> None:
    settings = Settings(connector_release_metadata_json=raw)
    assert admitted_connector_release(settings) is None


def test_production_config_requires_exact_admitted_connector_release() -> None:
    with pytest.raises(ValidationError, match="admitted Connector release"):
        production_settings("")
    with pytest.raises(ValidationError, match="admitted Connector release"):
        production_settings('{"version":"0.1.0"}')

    settings = production_settings(json.dumps(release_metadata()))
    assert admitted_connector_release(settings) is not None


async def test_production_startup_rechecks_connector_release_admission() -> None:
    settings = production_settings(json.dumps(release_metadata()))
    settings.connector_release_metadata_json = ""
    app = create_app(settings)
    settings.environment = "test"

    with pytest.raises(RuntimeError, match="admitted Connector release"):
        async with app.router.lifespan_context(app):
            pass


async def test_development_startup_rejects_nonempty_invalid_connector_metadata() -> None:
    settings = Settings(connector_release_metadata_json="not-json")
    app = create_app(settings)

    with pytest.raises(RuntimeError, match="empty development metadata"):
        async with app.router.lifespan_context(app):
            pass


async def test_production_readiness_rejects_missing_or_drifted_connector_release(
    harness: Harness,
) -> None:
    initial = release_metadata()
    harness.settings.connector_release_metadata_json = json.dumps(initial)
    harness.settings.sub2api_contract_marker = harness.settings.required_sub2api_contract_marker
    harness.settings.environment = "production"
    harness.app.state.connector_release_required = True
    metadata_sha256 = connector_release_metadata_sha256(
        harness.settings.connector_release_metadata_json
    )
    assert metadata_sha256 is not None
    harness.app.state.connector_release_raw_sha256_admission = metadata_sha256
    harness.app.state.connector_release_admission = admitted_connector_release(harness.settings)

    admitted = await harness.client.get("/v1/health/ready")
    assert admitted.status_code == 200
    assert admitted.json()["checks"]["connector_release"] == "ok"
    assert (await exchange(harness, "connector-snapshot-access-token")).status_code == 201

    harness.settings.connector_release_metadata_json = json.dumps(initial, indent=2)
    raw_drift_rejected = await harness.client.get("/v1/health/ready")
    assert raw_drift_rejected.status_code == 503
    assert raw_drift_rejected.json()["checks"]["connector_release"] == "failed"
    bootstrap = await harness.client.get("/v1/bootstrap")
    assert bootstrap.status_code == 200
    assert bootstrap.json()["connector_release"] == initial

    drifted = copy.deepcopy(initial)
    drifted["source_commit"] = "c" * 40
    harness.settings.connector_release_metadata_json = json.dumps(drifted)
    drift_rejected = await harness.client.get("/v1/health/ready")
    assert drift_rejected.status_code == 503
    assert drift_rejected.json()["checks"]["connector_release"] == "failed"

    harness.settings.connector_release_metadata_json = ""
    missing_rejected = await harness.client.get("/v1/health/ready")
    assert missing_rejected.status_code == 503
    assert missing_rejected.json()["checks"]["connector_release"] == "failed"


async def test_bootstrap_projects_only_admitted_connector_release_metadata(
    harness: Harness,
) -> None:
    harness.settings.connector_release_metadata_json = json.dumps(release_metadata())
    assert (await exchange(harness)).status_code == 201

    response = await harness.client.get("/v1/bootstrap")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["connector_release"] == release_metadata()

    invalid = release_metadata()
    invalid["assets"][0]["download_url"] = invalid["assets"][0]["download_url"].replace(
        "github.com", "github.example"
    )
    harness.settings.connector_release_metadata_json = json.dumps(invalid)
    rejected = await harness.client.get("/v1/bootstrap")
    assert rejected.status_code == 200
    assert rejected.json()["connector_release"] is None
