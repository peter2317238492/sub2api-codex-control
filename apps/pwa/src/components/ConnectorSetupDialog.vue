<script setup lang="ts">
import { Check, Copy, Download, KeyRound, Play, X } from "@lucide/vue";
import { computed, ref, watch } from "vue";

import type {
  ConnectorArchitecture,
  ConnectorOperatingSystem,
  ConnectorPackageFormat,
  ConnectorReleaseAsset,
  ConnectorReleaseMetadata,
} from "@/types";

const props = defineProps<{
  open: boolean;
  metadata: ConnectorReleaseMetadata | null;
}>();

const emit = defineEmits<{
  close: [];
  pair: [];
}>();

const os = ref<ConnectorOperatingSystem>("linux");
const arch = ref<ConnectorArchitecture>("amd64");
const packageFormat = ref<ConnectorPackageFormat>("deb");
const deviceName = ref("");
const workspaceRoot = ref("");
const initConfirmed = ref(false);
const pairConfirmed = ref(false);
const copied = ref<"install" | "init" | "pair" | null>(null);
const copyError = ref<string | null>(null);

const sha256Pattern = /^[0-9a-f]{64}$/;
const gitCommitPattern = /^[0-9a-f]{40}$/;
const filenamePattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const trustedRepository = "https://github.com/peter2317238492/sub2api-codex-control";
const expectedConfigPath = "~/.config/sub2api-codex-connector/connector.json";
const expectedPairCommand = "sub2api-codex-connector-ctl pair";
const expectedStartCommand = "sub2api-codex-connector-ctl start";
const expectedTuples = new Set([
  "linux:amd64:deb",
  "linux:amd64:rpm",
  "linux:arm64:deb",
  "linux:arm64:rpm",
  "darwin:amd64:pkg",
  "darwin:arm64:pkg",
]);
const metadataKeys = [
  "format_version", "release_mode", "releasable", "source_repository", "source_commit",
  "version", "tag", "codex_version", "schema_digest", "manifest", "config_path_hint",
  "pair_command", "start_command", "assets",
] as const;
const fileEvidenceKeys = ["filename", "sha256", "size", "signature_bundle"] as const;
const sbomEvidenceKeys = ["format", ...fileEvidenceKeys] as const;
const provenanceEvidenceKeys = ["predicate_type", ...fileEvidenceKeys, "attestation_bundle"] as const;
const assetKeys = [
  "os", "arch", "package_format", "filename", "download_url", "sha256", "size",
  "signature_bundle", "sbom", "provenance",
] as const;
const allowedFormats: Record<ConnectorOperatingSystem, readonly ConnectorPackageFormat[]> = {
  linux: ["deb", "rpm"],
  darwin: ["pkg"],
};

function hasExactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function validFileEvidence(value: unknown, filename: string, signatureBundle: string): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const evidence = value as Record<string, unknown>;
  return (
    evidence.filename === filename &&
    filenamePattern.test(evidence.filename as string) &&
    sha256Pattern.test(evidence.sha256 as string) &&
    Number.isSafeInteger(evidence.size) &&
    (evidence.size as number) > 0 &&
    evidence.signature_bundle === signatureBundle &&
    filenamePattern.test(evidence.signature_bundle as string)
  );
}

function assetFilename(asset: ConnectorReleaseAsset, version: string): string {
  return `sub2api-codex-connector_${version}_${asset.os}_${asset.arch}.${asset.package_format}`;
}

function isHttpsAsset(asset: ConnectorReleaseAsset, metadata: ConnectorReleaseMetadata): boolean {
  try {
    const url = new URL(asset.download_url);
    return (
      url.origin === "https://github.com" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      asset.download_url ===
        `${trustedRepository}/releases/download/${metadata.tag}/${assetFilename(asset, metadata.version)}`
    );
  } catch {
    return false;
  }
}

function validMetadata(metadata: ConnectorReleaseMetadata | null): metadata is ConnectorReleaseMetadata {
  if (
    !metadata ||
    !hasExactKeys(metadata, metadataKeys) ||
    metadata.format_version !== 1 ||
    metadata.release_mode !== "release" ||
    metadata.releasable !== true ||
    metadata.source_repository !== trustedRepository ||
    !gitCommitPattern.test(metadata.source_commit) ||
    !versionPattern.test(metadata.version) ||
    metadata.tag !== `connector-v${metadata.version}` ||
    !versionPattern.test(metadata.codex_version) ||
    !sha256Pattern.test(metadata.schema_digest) ||
    metadata.config_path_hint !== expectedConfigPath ||
    metadata.pair_command !== expectedPairCommand ||
    metadata.start_command !== expectedStartCommand ||
    !hasExactKeys(metadata.manifest, fileEvidenceKeys) ||
    !validFileEvidence(metadata.manifest, "manifest.json", "manifest.json.sigstore.json") ||
    !Array.isArray(metadata.assets) ||
    metadata.assets.length !== expectedTuples.size
  ) return false;

  const tuples = new Set<string>();
  const validAssets = (metadata.assets as unknown[]).every((candidate) => {
    if (!hasExactKeys(candidate, assetKeys)) return false;
    const asset = candidate as unknown as ConnectorReleaseAsset;
    const tuple = `${asset.os}:${asset.arch}:${asset.package_format}`;
    const filename = assetFilename(asset, metadata.version);
    const sbomFilename = `${filename}.spdx.json`;
    const provenanceFilename = `${filename}.intoto.json`;
    if (
      !expectedTuples.has(tuple) ||
      !allowedFormats[asset.os]?.includes(asset.package_format) ||
      !["amd64", "arm64"].includes(asset.arch) ||
      !validFileEvidence(asset, filename, `${filename}.sigstore.json`) ||
      !hasExactKeys(asset.sbom, sbomEvidenceKeys) ||
      asset.sbom.format !== "SPDX-2.3-json" ||
      !validFileEvidence(asset.sbom, sbomFilename, `${sbomFilename}.sigstore.json`) ||
      !hasExactKeys(asset.provenance, provenanceEvidenceKeys) ||
      asset.provenance.predicate_type !== "https://slsa.dev/provenance/v1" ||
      asset.provenance.attestation_bundle !== `${filename}.intoto.sigstore.json` ||
      !filenamePattern.test(asset.provenance.attestation_bundle) ||
      !validFileEvidence(
        asset.provenance,
        provenanceFilename,
        `${provenanceFilename}.sigstore.json`,
      ) ||
      !isHttpsAsset(asset, metadata) ||
      tuples.has(tuple)
    ) return false;
    tuples.add(tuple);
    return true;
  });
  return validAssets && [...expectedTuples].every((tuple) => tuples.has(tuple));
}

const release = computed(() => (validMetadata(props.metadata) ? props.metadata : null));
const origin = computed(() => window.location.origin);
const secureOrigin = computed(() => origin.value.startsWith("https://"));
const availableOs = computed(() => [...new Set(release.value?.assets.map((asset) => asset.os) ?? [])]);
const availableArch = computed(() => [
  ...new Set(release.value?.assets.filter((asset) => asset.os === os.value).map((asset) => asset.arch) ?? []),
]);
const availableFormats = computed(() => [
  ...new Set(
    release.value?.assets
      .filter((asset) => asset.os === os.value && asset.arch === arch.value)
      .map((asset) => asset.package_format) ?? [],
  ),
]);
const selectedAsset = computed(() =>
  release.value?.assets.find(
    (asset) => asset.os === os.value && asset.arch === arch.value && asset.package_format === packageFormat.value,
  ) ?? null,
);

function resetSelections(): void {
  const firstAsset = release.value?.assets[0];
  if (firstAsset) {
    os.value = firstAsset.os;
    arch.value = firstAsset.arch;
    packageFormat.value = firstAsset.package_format;
  }
}

watch([release, os, arch], () => {
  if (!availableOs.value.includes(os.value)) os.value = availableOs.value[0] ?? "linux";
  if (!availableArch.value.includes(arch.value)) arch.value = availableArch.value[0] ?? "amd64";
  if (!availableFormats.value.includes(packageFormat.value)) packageFormat.value = availableFormats.value[0] ?? "deb";
}, { immediate: true });

watch(() => props.open, (open) => {
  if (!open) return;
  resetSelections();
  initConfirmed.value = false;
  pairConfirmed.value = false;
  copied.value = null;
  copyError.value = null;
});

function isAbsolutePath(value: string): boolean {
  return value.startsWith("/") && !/[\u0000-\u001f]/.test(value);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

const configValid = computed(() => (
  release.value !== null &&
  secureOrigin.value &&
  deviceName.value.trim().length > 0 &&
  deviceName.value.trim().length <= 255 &&
  !/[\u0000-\u001f]/.test(deviceName.value) &&
  isAbsolutePath(workspaceRoot.value.trim())
));

const initCommand = computed(() => {
  if (!release.value || !configValid.value) return "";
  return [
    "sub2api-codex-connector-ctl init",
    `--origin ${shellQuote(origin.value)}`,
    `--workspace ${shellQuote(workspaceRoot.value.trim())}`,
    `--display-name ${shellQuote(deviceName.value.trim())}`,
  ].join(" ");
});

const installCommand = computed(() => {
  const asset = selectedAsset.value;
  if (!asset || !release.value) return "";
  const filename = assetFilename(asset, release.value.version);
  const localFile = `./${filename}`;
  const checksumInput = `printf '%s  %s\\n' ${shellQuote(asset.sha256)} ${shellQuote(localFile)}`;
  const verify = asset.os === "darwin"
    ? `${checksumInput} | /usr/bin/shasum -a 256 --check -`
    : `${checksumInput} | sha256sum --check --strict -`;
  if (asset.package_format === "deb") return `${verify} && sudo apt install ${shellQuote(localFile)}`;
  if (asset.package_format === "rpm") return `${verify} && sudo dnf install ${shellQuote(localFile)}`;
  return `${verify} && open ${shellQuote(localFile)}`;
});

async function copyCommand(value: string, kind: "install" | "init" | "pair"): Promise<void> {
  if (!value || !navigator.clipboard?.writeText) {
    copyError.value = "浏览器无法访问剪贴板，请手动选择命令。";
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
    copied.value = kind;
    copyError.value = null;
  } catch {
    copyError.value = "复制失败，请手动选择命令。";
  }
}

function beginPairing(): void {
  if (!pairConfirmed.value) return;
  emit("pair");
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
    <section class="dialog setup-dialog" role="dialog" aria-modal="true" aria-labelledby="connector-setup-title">
      <header>
        <div>
          <span class="eyebrow">设备</span>
          <h2 id="connector-setup-title">设置 Connector</h2>
        </div>
        <button class="icon-button" type="button" title="关闭" @click="$emit('close')"><X :size="19" /></button>
      </header>

      <div class="setup-content">
        <div v-if="!release" class="release-unavailable" role="status">
          <strong>正式安装包暂不可用</strong>
          <p>发布元数据尚未就绪或未通过校验。已有 Connector 仍可继续配对。</p>
          <button class="primary-button existing-pair-button" type="button" @click="$emit('pair')"><KeyRound :size="17" />配对已有 Connector</button>
        </div>

        <template v-else>
          <section class="setup-step">
            <div class="step-heading"><span>1</span><div><h3>下载安装包</h3><p>{{ release.tag }} · v{{ release.version }}</p></div></div>
            <div class="selector-grid">
              <label>平台<select v-model="os" class="standalone-select"><option v-for="item in availableOs" :key="item" :value="item">{{ item === "darwin" ? "macOS" : "Linux" }}</option></select></label>
              <label>架构<select v-model="arch" class="standalone-select"><option v-for="item in availableArch" :key="item" :value="item">{{ item }}</option></select></label>
              <label>格式<select v-model="packageFormat" class="standalone-select"><option v-for="item in availableFormats" :key="item" :value="item">.{{ item }}</option></select></label>
            </div>
            <div v-if="selectedAsset" class="asset-row">
              <code>SHA-256 {{ selectedAsset.sha256 }}</code>
              <a class="primary-button asset-download" :href="selectedAsset.download_url"><Download :size="17" />下载 .{{ selectedAsset.package_format }}</a>
            </div>
            <p class="step-note">下载后，在安装包所在目录执行下方命令；校验不通过时不会安装。此步骤不需要 Sub2API 管理员，但 Linux 会使用本机 sudo，macOS 也可能要求本机管理员授权。</p>
            <div v-if="installCommand" class="command-row install-command">
              <code>{{ installCommand }}</code>
              <button class="icon-button" type="button" title="复制校验与安装命令" @click="copyCommand(installCommand, 'install')">
                <Check v-if="copied === 'install'" :size="17" />
                <Copy v-else :size="17" />
              </button>
            </div>
          </section>

          <section class="setup-step">
            <div class="step-heading"><span>2</span><div><h3>初始化设备</h3><p>使用运行 Connector 的普通用户 · {{ release.config_path_hint }}</p></div></div>
            <div class="setup-form">
              <label>Control origin<input :value="origin" readonly /></label>
              <label>设备名称<input v-model="deviceName" maxlength="255" placeholder="我的设备" /></label>
              <label class="workspace-field">Workspace root<input v-model="workspaceRoot" placeholder="/absolute/path/to/workspace" /></label>
            </div>
            <p class="step-note">配置路径固定为 {{ release.config_path_hint }}；非空的 XDG_CONFIG_HOME override 会被管理命令拒绝。</p>
            <p v-if="!secureOrigin" class="form-error">只能从 HTTPS Control origin 生成正式配置。</p>
            <div v-if="initCommand" class="command-row init-command">
              <code>{{ initCommand }}</code>
              <button class="icon-button" type="button" title="复制初始化命令" @click="copyCommand(initCommand, 'init')">
                <Check v-if="copied === 'init'" :size="17" />
                <Copy v-else :size="17" />
              </button>
            </div>
            <label class="step-confirm"><input v-model="initConfirmed" type="checkbox" :disabled="!configValid" /><span>初始化命令已成功创建私有配置</span></label>
          </section>

          <section class="setup-step">
            <div class="step-heading"><span>3</span><div><h3>生成配对码</h3><p>配对完成后再启动后台服务</p></div></div>
            <div class="command-row pair-command">
              <code>{{ release.pair_command }}</code>
              <button class="icon-button" type="button" title="复制配对命令" :disabled="!initConfirmed" @click="copyCommand(release.pair_command, 'pair')">
                <Check v-if="copied === 'pair'" :size="17" />
                <Copy v-else :size="17" />
              </button>
            </div>
            <label class="step-confirm"><input v-model="pairConfirmed" type="checkbox" :disabled="!initConfirmed" /><span>配对命令已显示一次性配对码</span></label>
          </section>

          <section class="setup-step final-step">
            <div class="step-heading"><span>4</span><div><h3>输入配对码</h3><p>使用配对命令显示的一次性配对码。</p></div></div>
            <button class="primary-button begin-pair-button" type="button" :disabled="!pairConfirmed" @click="beginPairing"><Play :size="17" />进入配对</button>
          </section>
          <p v-if="copyError" class="form-error setup-copy-error" role="status">{{ copyError }}</p>
        </template>
      </div>
    </section>
  </div>
</template>

<style scoped>
.setup-dialog { width: min(680px, 100%); max-height: min(820px, calc(100vh - 32px)); overflow: hidden; }
.setup-content { max-height: calc(100vh - 105px); overflow: auto; }
.setup-step { padding: 18px; border-bottom: 1px solid var(--line); }
.final-step { border-bottom: 0; }
.step-heading { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 14px; }
.step-heading > span { display: grid; width: 24px; height: 24px; flex: 0 0 24px; place-items: center; color: white; background: var(--surface-dark); border-radius: 50%; font-size: 11px; font-weight: 800; }
.step-heading h3 { margin: 1px 0 2px; font-size: 13px; }
.step-heading p { margin: 0; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
.selector-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.selector-grid label, .setup-form > label { display: flex; min-width: 0; flex-direction: column; gap: 6px; color: #525a56; font-size: 11px; font-weight: 700; }
.asset-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; }
.asset-row code { min-width: 0; overflow: hidden; color: var(--muted); font-size: 10px; text-overflow: ellipsis; }
.asset-download { flex: 0 0 auto; }
.step-note { margin: 10px 0 0; color: var(--muted); font-size: 11px; line-height: 1.5; }
.setup-form { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.setup-form input { width: 100%; min-width: 0; height: 40px; padding: 0 10px; background: var(--surface); border: 1px solid var(--line-strong); border-radius: 6px; font-size: 12px; }
.setup-form input[readonly] { color: var(--muted); background: #f3f5f4; }
.workspace-field { grid-column: 1 / -1; }
.command-row { display: flex; align-items: center; gap: 8px; margin-top: 12px; padding: 8px 8px 8px 10px; background: #f3f5f4; border: 1px solid var(--line); border-radius: 6px; }
.command-row code { min-width: 0; flex: 1; color: #444b47; font-size: 10px; overflow-wrap: anywhere; user-select: all; }
.command-row .icon-button { flex: 0 0 34px; }
.step-confirm { display: flex; align-items: center; gap: 9px; margin-top: 12px; color: #525a56; font-size: 12px; }
.step-confirm input { width: 16px; height: 16px; }
.begin-pair-button { margin-left: 34px; }
.setup-copy-error { margin: 0; padding: 10px 18px 16px; }
.release-unavailable { padding: 36px 22px; text-align: center; }
.release-unavailable strong { font-size: 14px; }
.release-unavailable p { margin: 8px auto 18px; color: var(--muted); font-size: 12px; }
@media (max-width: 600px) { .selector-grid, .setup-form { grid-template-columns: 1fr; } .asset-row { align-items: stretch; flex-direction: column; } .asset-row code { white-space: normal; overflow-wrap: anywhere; } }
</style>
