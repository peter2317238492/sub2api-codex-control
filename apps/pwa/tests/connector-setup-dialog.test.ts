import { mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectorSetupDialog from "@/components/ConnectorSetupDialog.vue";
import type { ConnectorReleaseMetadata } from "@/types";

const sha256 = "a".repeat(64);
function releaseAsset(
  os: "linux" | "darwin",
  arch: "amd64" | "arm64",
  packageFormat: "deb" | "rpm" | "pkg",
  digest: string,
) {
  const filename = `sub2api-codex-connector_0.1.0_${os}_${arch}.${packageFormat}`;
  return {
    os,
    arch,
    package_format: packageFormat,
    filename,
    download_url: `https://github.com/peter2317238492/sub2api-codex-control/releases/download/connector-v0.1.0/${filename}`,
    sha256: digest,
    size: 1000,
    signature_bundle: `${filename}.sigstore.json`,
    sbom: {
      format: "SPDX-2.3-json",
      filename: `${filename}.spdx.json`,
      sha256: "7".repeat(64),
      size: 2000,
      signature_bundle: `${filename}.spdx.json.sigstore.json`,
    },
    provenance: {
      predicate_type: "https://slsa.dev/provenance/v1",
      filename: `${filename}.intoto.json`,
      sha256: "8".repeat(64),
      size: 3000,
      signature_bundle: `${filename}.intoto.json.sigstore.json`,
      attestation_bundle: `${filename}.intoto.sigstore.json`,
    },
  } as const;
}

const metadata: ConnectorReleaseMetadata = {
  format_version: 1,
  release_mode: "release",
  releasable: true,
  source_repository: "https://github.com/peter2317238492/sub2api-codex-control",
  source_commit: "9".repeat(40),
  version: "0.1.0",
  tag: "connector-v0.1.0",
  codex_version: "0.147.0",
  schema_digest: "5".repeat(64),
  manifest: {
    filename: "manifest.json",
    sha256: "6".repeat(64),
    size: 4000,
    signature_bundle: "manifest.json.sigstore.json",
  },
  config_path_hint: "~/.config/sub2api-codex-connector/connector.json",
  pair_command: "sub2api-codex-connector-ctl pair",
  start_command: "sub2api-codex-connector-ctl start",
  assets: [
    releaseAsset("linux", "amd64", "deb", sha256),
    releaseAsset("linux", "amd64", "rpm", "b".repeat(64)),
    releaseAsset("linux", "arm64", "deb", "c".repeat(64)),
    releaseAsset("linux", "arm64", "rpm", "d".repeat(64)),
    releaseAsset("darwin", "amd64", "pkg", "e".repeat(64)),
    releaseAsset("darwin", "arm64", "pkg", "f".repeat(64)),
  ],
};

describe("ConnectorSetupDialog", () => {
  beforeEach(() => (window as unknown as { happyDOM: { setURL: (url: string) => void } }).happyDOM.setURL("https://control.example.test/codex/"));
  afterEach(() => vi.restoreAllMocks());

  it("shows only the exact selected formal release asset and its fixed identity", async () => {
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata } });
    expect(wrapper.text()).toContain("connector-v0.1.0");
    expect(wrapper.text()).toContain(sha256);
    expect(wrapper.get(".asset-download").attributes("href")).toBe(metadata.assets[0]!.download_url);
    expect(wrapper.get(".install-command code").text()).toContain("sha256sum --check --strict -");
    expect(wrapper.get(".install-command code").text()).toContain(sha256);
    expect(wrapper.get(".install-command code").text()).toContain("sudo apt install");
    expect(wrapper.text()).toContain("不需要 Sub2API 管理员");
    expect(wrapper.text()).toContain("非空的 XDG_CONFIG_HOME override 会被管理命令拒绝");

    await wrapper.findAll("select")[0]!.setValue("darwin");
    expect(wrapper.get(".asset-download").attributes("href")).toBe(metadata.assets[4]!.download_url);
    expect(wrapper.text()).toContain("e".repeat(64));
    expect(wrapper.get(".install-command code").text()).toContain("/usr/bin/shasum -a 256 --check -");
    expect(wrapper.get(".install-command code").text()).toContain("&& open");
  });

  it("fails closed without admitted metadata while preserving existing pairing", async () => {
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata: null } });
    expect(wrapper.text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);
    expect(wrapper.find(".config-download").exists()).toBe(false);
    await wrapper.get(".existing-pair-button").trigger("click");
    expect(wrapper.emitted("pair")).toHaveLength(1);
  });

  it("rejects an asset whose URL is not bound to the fixed tag", () => {
    const invalid = structuredClone(metadata);
    invalid.assets[0]!.download_url = "https://github.com/peter2317238492/sub2api-codex-control/releases/latest/download/connector.deb";
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata: invalid } });
    expect(wrapper.text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);
  });

  it("rejects incomplete or relationally inconsistent signed evidence", () => {
    const invalid = structuredClone(metadata);
    invalid.assets[0]!.provenance.attestation_bundle = "other.intoto.sigstore.json";
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata: invalid } });
    expect(wrapper.text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);
  });

  it("fails closed instead of crashing on a malformed bootstrap asset", () => {
    const malformed = structuredClone(metadata) as unknown as ConnectorReleaseMetadata;
    (malformed.assets as unknown[])[0] = null;
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata: malformed } });
    expect(wrapper.text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);
  });

  it("generates a safely quoted ctl init command and separates pair from service start", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata } });

    const inputs = wrapper.findAll("input");
    await inputs.find((input) => input.attributes("placeholder") === "我的设备")!.setValue("O'Brien Laptop");
    await inputs.find((input) => input.attributes("placeholder") === "/absolute/path/to/workspace")!.setValue("/Users/test/O'Brien project");

    const init = wrapper.get(".init-command code").text();
    expect(init).toContain("sub2api-codex-connector-ctl init");
    expect(init).toContain("--origin 'https://control.example.test'");
    expect(init).toContain(`--workspace '/Users/test/O'\"'\"'Brien project'`);
    expect(init).toContain(`--display-name 'O'\"'\"'Brien Laptop'`);
    expect(wrapper.get(".begin-pair-button").attributes("disabled")).toBeDefined();

    await wrapper.get(".init-command button").trigger("click");
    expect(writeText).toHaveBeenCalledWith(init);
    const confirmations = wrapper.findAll('.step-confirm input[type="checkbox"]');
    await confirmations[0]!.setValue(true);
    await wrapper.get(".pair-command button").trigger("click");
    expect(writeText).toHaveBeenCalledWith("sub2api-codex-connector-ctl pair");
    await confirmations[1]!.setValue(true);
    await wrapper.get(".begin-pair-button").trigger("click");
    expect(wrapper.emitted("pair")).toHaveLength(1);
  });

  it("rejects incomplete package inventories and lookalike repositories", () => {
    const incomplete = structuredClone(metadata);
    incomplete.assets.pop();
    expect(mount(ConnectorSetupDialog, { props: { open: true, metadata: incomplete } }).find(".asset-download").exists()).toBe(false);

    const lookalike = structuredClone(metadata);
    lookalike.source_repository = "https://github.com/peter2317238492/sub2api-codex-control";
    lookalike.assets[0]!.download_url = lookalike.assets[0]!.download_url.replace("github.com/", "github.example/");
    expect(mount(ConnectorSetupDialog, { props: { open: true, metadata: lookalike } }).find(".asset-download").exists()).toBe(false);
  });
});
