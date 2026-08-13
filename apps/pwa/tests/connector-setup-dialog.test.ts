import { mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectorSetupDialog from "@/components/ConnectorSetupDialog.vue";
import type { ConnectorReleaseMetadata } from "@/types";

const sha256 = "a".repeat(64);
const metadata: ConnectorReleaseMetadata = {
  release_mode: "release",
  releasable: true,
  version: "0.1.0",
  tag: "connector-v0.1.0",
  codex_version: "0.147.0",
  schema_digest: "5".repeat(64),
  config_path_hint: "~/.config/sub2api-codex-connector/connector.json",
  start_command: "sub2api-codex-connector-ctl pair",
  assets: [
    { os: "linux", arch: "amd64", package_format: "deb", download_url: "https://github.com/example/repo/releases/download/connector-v0.1.0/connector.deb", sha256 },
    { os: "linux", arch: "amd64", package_format: "rpm", download_url: "https://github.com/example/repo/releases/download/connector-v0.1.0/connector.rpm", sha256: "b".repeat(64) },
    { os: "darwin", arch: "arm64", package_format: "pkg", download_url: "https://github.com/example/repo/releases/download/connector-v0.1.0/connector.pkg", sha256: "c".repeat(64) },
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

    await wrapper.findAll("select")[0]!.setValue("darwin");
    expect(wrapper.get(".asset-download").attributes("href")).toBe(metadata.assets[2]!.download_url);
    expect(wrapper.text()).toContain("c".repeat(64));
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
    invalid.assets[0]!.download_url = "https://github.com/example/repo/releases/latest/download/connector.deb";
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata: invalid } });
    expect(wrapper.text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);
  });

  it("generates an origin-bound pinned configuration and gates pairing on startup confirmation", async () => {
    const createObjectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:connector-config");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const wrapper = mount(ConnectorSetupDialog, { props: { open: true, metadata } });

    const inputs = wrapper.findAll("input");
    await inputs.find((input) => input.attributes("placeholder") === "我的设备")!.setValue("Laptop");
    await inputs.find((input) => input.attributes("placeholder") === "/absolute/path/to/state")!.setValue("/Users/test/.local/state/connector");
    await wrapper.get('input[aria-label="Workspace root 1"]').setValue("/Users/test/project");

    const preview = wrapper.get(".config-preview pre").text();
    expect(preview).toContain('"control_url": "wss://control.example.test/codex-ws/device"');
    expect(preview).toContain('"codex_version": "0.147.0"');
    expect(preview).toContain(`"schema_digest": "${metadata.schema_digest}"`);
    expect(wrapper.get(".begin-pair-button").attributes("disabled")).toBeDefined();

    await wrapper.get(".config-download").trigger("click");
    expect(createObjectURL).toHaveBeenCalledOnce();
    const confirmation = wrapper.get('.start-confirm input[type="checkbox"]');
    expect(confirmation.attributes("disabled")).toBeUndefined();
    await confirmation.setValue(true);
    await wrapper.get(".begin-pair-button").trigger("click");
    expect(wrapper.emitted("pair")).toHaveLength(1);
  });
});
