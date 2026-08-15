from __future__ import annotations

import copy
import importlib.util
import json
import re
import unittest
from pathlib import Path
from typing import Any


PACKAGE_DIR = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PACKAGE_DIR / "server-packages.schema.json"
MODULE_PATH = PACKAGE_DIR / "server_package.py"


def load_module() -> Any:
    spec = importlib.util.spec_from_file_location("server_package_schema_test", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load server package module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise AssertionError(f"non-local schema reference: {reference}")
    value: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        value = value[part]
    if not isinstance(value, dict):
        raise AssertionError(f"schema reference is not an object: {reference}")
    return value


def assert_schema(instance: Any, schema: dict[str, Any], root: dict[str, Any]) -> None:
    """Validate the small, deliberate JSON Schema keyword set used by this file."""

    if "$ref" in schema:
        assert_schema(instance, resolve_ref(root, schema["$ref"]), root)
    for branch in schema.get("allOf", []):
        assert_schema(instance, branch, root)
    if "if" in schema:
        try:
            assert_schema(instance, schema["if"], root)
        except AssertionError:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            assert_schema(instance, branch, root)
    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            try:
                assert_schema(instance, branch, root)
            except AssertionError:
                continue
            matches += 1
        if matches != 1:
            raise AssertionError(f"oneOf matched {matches} branches")
    if "const" in schema and instance != schema["const"]:
        raise AssertionError(f"{instance!r} differs from const {schema['const']!r}")

    expected_type = schema.get("type")
    if expected_type == "object" and not isinstance(instance, dict):
        raise AssertionError("value is not an object")
    if expected_type == "array" and not isinstance(instance, list):
        raise AssertionError("value is not an array")
    if expected_type == "string" and not isinstance(instance, str):
        raise AssertionError("value is not a string")
    if expected_type == "integer" and type(instance) is not int:
        raise AssertionError("value is not an integer")

    if isinstance(instance, str) and "pattern" in schema:
        if re.search(schema["pattern"], instance) is None:
            raise AssertionError(f"string does not match {schema['pattern']}")
    if type(instance) is int:
        if instance < schema.get("minimum", instance):
            raise AssertionError("integer is below minimum")
        if instance > schema.get("maximum", instance):
            raise AssertionError("integer is above maximum")

    if isinstance(instance, dict):
        required = set(schema.get("required", []))
        if not required.issubset(instance):
            raise AssertionError(f"missing required keys: {sorted(required - set(instance))}")
        minimum = schema.get("minProperties", 0)
        maximum = schema.get("maxProperties", len(instance))
        if not minimum <= len(instance) <= maximum:
            raise AssertionError("object property count is outside bounds")
        property_names = schema.get("propertyNames")
        if property_names is not None:
            for name in instance:
                assert_schema(name, property_names, root)
        properties = schema.get("properties", {})
        for name, child_schema in properties.items():
            if name in instance:
                assert_schema(instance[name], child_schema, root)
        extras = set(instance) - set(properties)
        additional = schema.get("additionalProperties", True)
        if extras and additional is False:
            raise AssertionError(f"unexpected properties: {sorted(extras)}")
        if extras and isinstance(additional, dict):
            for name in extras:
                assert_schema(instance[name], additional, root)

    if isinstance(instance, list):
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", len(instance))
        if not minimum <= len(instance) <= maximum:
            raise AssertionError("array size is outside bounds")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(value, sort_keys=True) for value in instance]
            if len(encoded) != len(set(encoded)):
                raise AssertionError("array items are not unique")
        if "items" in schema:
            for value in instance:
                assert_schema(value, schema["items"], root)


def file_record(filename: str, digest: str = "a" * 64, size: int = 100) -> dict[str, Any]:
    return {"filename": filename, "sha256": digest, "size": size}


def package(mode: str) -> dict[str, Any]:
    release = "1.2.3"
    target = f"server-{mode}-linux-amd64"
    filename = f"sub2api-codex-control-server-{release}-linux-amd64-{mode}.tar.gz"
    archive_sha = "b" * 64
    sbom_sha = "c" * 64
    sbom_name = f"{target}.{sbom_sha}.spdx.json"
    provenance_name = f"{filename}.provenance.json"
    return {
        "filename": filename,
        "sha256": archive_sha,
        "size": 101,
        "target_id": target,
        "mode": mode,
        "platform": "linux/amd64",
        "internal_manifest_sha256": "d" * 64,
        "signature_bundle": f"{filename}.sigstore.json",
        "delivery": {
            "kind": "single",
            "parts": [
                {
                    "filename": filename,
                    "sha256": archive_sha,
                    "size": 101,
                    "index": 1,
                    "count": 1,
                    "signature_bundle": f"{filename}.sigstore.json",
                }
            ],
        },
        "sbom": {
            **file_record(sbom_name, sbom_sha),
            "format": "SPDX-2.3-json",
            "signature_bundle": f"{sbom_name}.sigstore.json",
        },
        "provenance": {
            **file_record(provenance_name, "e" * 64),
            "predicate_type": "https://slsa.dev/provenance/v1",
            "signature_bundle": f"{provenance_name}.sigstore.json",
            "attestation_bundle": f"{filename}.intoto.sigstore.json",
        },
    }


def manifest() -> dict[str, Any]:
    commit = "1" * 40
    evidence = {
        name: "a" * 64
        for name in (
            "control-images.lock.json",
            "control-images.lock.sigstore.json",
            "source.tar",
            "source-files.manifest",
            "source-attestation.json",
            "control-api.spdx.json",
            "control-api.provenance.json",
            "pwa.spdx.json",
            "pwa.provenance.json",
            "postgres-tools.spdx.json",
            "postgres-tools.provenance.json",
        )
    }
    connector = {
        "source_repository": "https://github.com/owner/project",
        "source_commit": "2" * 40,
        "version": "4.5.6",
        "tag": "connector-v4.5.6",
        "release_id": 10,
        "workflow_run_id": 20,
        "workflow_run_attempt": 1,
        "metadata": file_record("connector-release-metadata.json"),
        "metadata_bundle": file_record("connector-release-metadata.json.sigstore.json"),
        "aggregate": file_record("connector-public-verification-aggregate.json"),
        "aggregate_bundle": file_record(
            "connector-public-verification-aggregate.json.sigstore.json"
        ),
    }
    return {
        "$schema": "https://sub2api-codex.invalid/schemas/server-packages-v1.json",
        "kind": "server-packages-manifest-v1",
        "format_version": 1,
        "release": "1.2.3",
        "release_tag": "control-v1.2.3",
        "platform": "linux/amd64",
        "source": {
            "repository": "https://github.com/owner/project",
            "commit": commit,
            "ref": "refs/tags/control-v1.2.3",
        },
        "builder": {
            "workflow_identity": (
                "https://github.com/owner/project/.github/workflows/"
                "control-images-release.yml@refs/tags/control-v1.2.3"
            ),
            "workflow_sha": commit,
            "workflow_trigger": "push",
            "invocation_id": "https://github.com/owner/project/actions/runs/12/attempts/1",
            "cosign_version": "v3.0.6",
            "syft_version": "v1.33.0",
        },
        "control_release": {
            "lock": file_record("control-images.lock.json"),
            "bundle": file_record("control-images.lock.sigstore.json"),
            "evidence_sha256s": evidence,
        },
        "oci_export": file_record("oci-export-receipt.json"),
        "consumer_verifier": file_record("server-package-verify.py"),
        "connector_release": connector,
        "packages": {"online": package("online"), "offline": package("offline")},
        "checksums": {
            "filename": "server-packages.sha256",
            "signature_bundle": "server-packages.sha256.sigstore.json",
        },
        "signing": {
            "cosign_version": "v3.0.6",
            "manifest_bundle": "server-packages.manifest.json.sigstore.json",
        },
    }


class ServerPackageSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.module = load_module()

    def test_all_local_references_resolve(self) -> None:
        pending: list[Any] = [self.schema]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if "$ref" in value:
                    resolve_ref(self.schema, value["$ref"])
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)

    def test_representative_manifest_matches_schema_and_runtime(self) -> None:
        value = manifest()
        assert_schema(value, self.schema, self.schema)
        self.assertEqual(self.module.validate_release_manifest(value), value)

    def test_closed_top_level_and_target_identity(self) -> None:
        extra = manifest()
        extra["unexpected"] = True
        with self.assertRaises(AssertionError):
            assert_schema(extra, self.schema, self.schema)

        target = manifest()
        target["packages"]["offline"]["target_id"] = "server-online-linux-amd64"
        with self.assertRaises(AssertionError):
            assert_schema(target, self.schema, self.schema)

    def test_content_addressed_sbom_and_part_limit(self) -> None:
        sbom = manifest()
        sbom["packages"]["online"]["sbom"]["filename"] = "online.spdx.json"
        with self.assertRaises(AssertionError):
            assert_schema(sbom, self.schema, self.schema)

        part = manifest()
        part["packages"]["online"]["delivery"]["parts"][0]["size"] = 2**31
        with self.assertRaises(AssertionError):
            assert_schema(part, self.schema, self.schema)

        below_limit_split = manifest()
        package_value = below_limit_split["packages"]["offline"]
        package_value["delivery"] = {
            "kind": "split",
            "parts": [
                {
                    "filename": f"{package_value['filename']}.part-001-of-002",
                    "sha256": "f" * 64,
                    "size": 50,
                    "index": 1,
                    "count": 2,
                    "signature_bundle": (
                        f"{package_value['filename']}.part-001-of-002.sigstore.json"
                    ),
                },
                {
                    "filename": f"{package_value['filename']}.part-002-of-002",
                    "sha256": "0" * 64,
                    "size": 51,
                    "index": 2,
                    "count": 2,
                    "signature_bundle": (
                        f"{package_value['filename']}.part-002-of-002.sigstore.json"
                    ),
                },
            ],
        }
        with self.assertRaises(AssertionError):
            assert_schema(below_limit_split, self.schema, self.schema)
        with self.assertRaises(self.module.ServerPackageError):
            self.module.validate_release_manifest(below_limit_split)

    def test_connector_and_oci_records_are_fixed(self) -> None:
        connector = manifest()
        connector["connector_release"]["aggregate"]["filename"] = "other.json"
        with self.assertRaises(AssertionError):
            assert_schema(connector, self.schema, self.schema)

        receipt = manifest()
        receipt["oci_export"]["filename"] = "other.json"
        with self.assertRaises(AssertionError):
            assert_schema(receipt, self.schema, self.schema)

        verifier = manifest()
        verifier["consumer_verifier"]["filename"] = "other.py"
        with self.assertRaises(AssertionError):
            assert_schema(verifier, self.schema, self.schema)

    def test_control_evidence_names_and_root_digests_are_one_closure(self) -> None:
        renamed = manifest()
        evidence = renamed["control_release"]["evidence_sha256s"]
        evidence["other.json"] = evidence.pop("source.tar")
        with self.assertRaises(AssertionError):
            assert_schema(renamed, self.schema, self.schema)
        with self.assertRaises(self.module.ServerPackageError):
            self.module.validate_release_manifest(renamed)

        drifted = manifest()
        drifted["control_release"]["evidence_sha256s"][
            "control-images.lock.json"
        ] = "b" * 64
        with self.assertRaises(self.module.ServerPackageError):
            self.module.validate_release_manifest(drifted)


if __name__ == "__main__":
    unittest.main()
