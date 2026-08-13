<script setup lang="ts">
import { Download, FileJson, KeyRound, Play, Plus, Trash2, X } from "@lucide/vue";
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
const stateDir = ref("");
const workspaceRoots = ref([""]);
const sandbox = ref<"read-only" | "workspace-write">("workspace-write");
const configDownloaded = ref(false);
const startConfirmed = ref(false);

const sha256Pattern = /^[0-9a-f]{64}$/;
const versionPattern = /^\d+\.\d+\.\d+$/;
const allowedFormats: Record<ConnectorOperatingSystem, readonly ConnectorPackageFormat[]> = {
  linux: ["deb", "rpm"],
  darwin: ["pkg"],
};

function isHttpsAsset(asset: ConnectorReleaseAsset, tag: string): boolean {
  try {
    const url = new URL(asset.download_url);
    const pathParts = url.pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      pathParts.includes(tag) &&
      !pathParts.some((part) => part.toLowerCase() === "latest")
    );
  } catch {
    return false;
  }
}

function validMetadata(metadata: ConnectorReleaseMetadata | null): metadata is ConnectorReleaseMetadata {
  if (
    !metadata ||
    metadata.release_mode !== "release" ||
    metadata.releasable !== true ||
    !versionPattern.test(metadata.version) ||
    metadata.tag !== `connector-v${metadata.version}` ||
    !metadata.codex_version.trim() ||
    !sha256Pattern.test(metadata.schema_digest) ||
    !metadata.config_path_hint.trim() ||
    !metadata.start_command.trim() ||
    metadata.assets.length === 0
  ) return false;

  const tuples = new Set<string>();
  return metadata.assets.every((asset) => {
    const tuple = `${asset.os}:${asset.arch}:${asset.package_format}`;
    if (
      !allowedFormats[asset.os]?.includes(asset.package_format) ||
      !["amd64", "arm64"].includes(asset.arch) ||
      !sha256Pattern.test(asset.sha256) ||
      !isHttpsAsset(asset, metadata.tag) ||
      tuples.has(tuple)
    ) return false;
    tuples.add(tuple);
    return true;
  });
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
  configDownloaded.value = false;
  startConfirmed.value = false;
});

function isAbsolutePath(value: string): boolean {
  return value.startsWith("/") && !/[\u0000-\u001f]/.test(value);
}

const cleanedRoots = computed(() => workspaceRoots.value.map((root) => root.trim()));
const configValid = computed(() => (
  release.value !== null &&
  secureOrigin.value &&
  deviceName.value.trim().length > 0 &&
  isAbsolutePath(stateDir.value.trim()) &&
  cleanedRoots.value.length >= 1 &&
  cleanedRoots.value.length <= 32 &&
  cleanedRoots.value.every(isAbsolutePath) &&
  new Set(cleanedRoots.value).size === cleanedRoots.value.length
));

const configJson = computed(() => {
  if (!release.value || !configValid.value) return "";
  const controlOrigin = origin.value.replace(/^https:/, "wss:");
  return `${JSON.stringify({
    control_url: `${controlOrigin}/codex-ws/device`,
    pairing_url: `${origin.value}/codex-api/v1/device-pairings/start`,
    token_url: `${origin.value}/codex-api/v1/device/connect-token`,
    display_name: deviceName.value.trim(),
    state_dir: stateDir.value.trim(),
    workspace_roots: cleanedRoots.value,
    sandbox_cap: sandbox.value,
    codex_binary: "codex",
    codex_version: release.value.codex_version,
    schema_digest: release.value.schema_digest,
    heartbeat_interval: "20s",
    approval_timeout: "120s",
    pairing_poll_interval: "2s",
    reconnect_min: "1s",
    reconnect_max: "30s",
  }, null, 2)}\n`;
});

function addRoot(): void {
  if (workspaceRoots.value.length < 32) workspaceRoots.value.push("");
}

function removeRoot(index: number): void {
  if (workspaceRoots.value.length > 1) workspaceRoots.value.splice(index, 1);
}

function downloadConfig(): void {
  if (!configJson.value) return;
  const url = URL.createObjectURL(new Blob([configJson.value], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "connector.json";
  link.click();
  URL.revokeObjectURL(url);
  configDownloaded.value = true;
}

function beginPairing(): void {
  if (!startConfirmed.value) return;
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
          </section>

          <section class="setup-step">
            <div class="step-heading"><span>2</span><div><h3>生成配置</h3><p>{{ release.config_path_hint }}</p></div></div>
            <div class="setup-form">
              <label>Control origin<input :value="origin" readonly /></label>
              <label>设备名称<input v-model="deviceName" maxlength="255" placeholder="我的设备" /></label>
              <label>State directory<input v-model="stateDir" placeholder="/absolute/path/to/state" /></label>
              <fieldset>
                <legend>Workspace roots</legend>
                <div v-for="(_, index) in workspaceRoots" :key="index" class="root-row">
                  <input v-model="workspaceRoots[index]" :aria-label="`Workspace root ${index + 1}`" placeholder="/absolute/path/to/workspace" />
                  <button class="icon-button" type="button" title="移除此目录" :disabled="workspaceRoots.length === 1" @click="removeRoot(index)"><Trash2 :size="17" /></button>
                </div>
                <button class="secondary-button add-root-button" type="button" :disabled="workspaceRoots.length >= 32" @click="addRoot"><Plus :size="16" />添加目录</button>
              </fieldset>
              <label>Sandbox<select v-model="sandbox" class="standalone-select"><option value="workspace-write">Workspace write</option><option value="read-only">Read only</option></select></label>
            </div>
            <p v-if="!secureOrigin" class="form-error">只能从 HTTPS Control origin 生成正式配置。</p>
            <button class="secondary-button config-download" type="button" :disabled="!configValid" @click="downloadConfig"><FileJson :size="17" />下载 connector.json</button>
            <details v-if="configJson" class="config-preview"><summary>预览 connector.json</summary><pre>{{ configJson }}</pre></details>
          </section>

          <section class="setup-step">
            <div class="step-heading"><span>3</span><div><h3>启动 Connector</h3><p><code>{{ release.start_command }}</code></p></div></div>
            <label class="start-confirm"><input v-model="startConfirmed" type="checkbox" :disabled="!configDownloaded" /><span>我已按固定命令安装配置并启动 Connector</span></label>
          </section>

          <section class="setup-step final-step">
            <div class="step-heading"><span>4</span><div><h3>输入配对码</h3><p>Connector 启动后会显示一次性配对码。</p></div></div>
            <button class="primary-button begin-pair-button" type="button" :disabled="!startConfirmed" @click="beginPairing"><Play :size="17" />进入配对</button>
          </section>
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
.setup-form { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.setup-form input, .root-row input { width: 100%; min-width: 0; height: 40px; padding: 0 10px; background: var(--surface); border: 1px solid var(--line-strong); border-radius: 6px; font-size: 12px; }
.setup-form input[readonly] { color: var(--muted); background: #f3f5f4; }
.setup-form fieldset { grid-column: 1 / -1; margin: 0; padding: 0; border: 0; }
.setup-form legend { margin-bottom: 6px; color: #525a56; font-size: 11px; font-weight: 700; }
.root-row { display: flex; align-items: center; gap: 7px; margin-bottom: 7px; }
.add-root-button, .config-download { margin-top: 10px; }
.config-preview { margin-top: 12px; color: var(--muted); font-size: 11px; }
.config-preview pre { max-height: 180px; padding: 10px; overflow: auto; background: #f3f5f4; border: 1px solid var(--line); border-radius: 6px; color: #444b47; font-size: 10px; white-space: pre-wrap; }
.start-confirm { display: flex; align-items: center; gap: 9px; color: #525a56; font-size: 12px; }
.start-confirm input { width: 16px; height: 16px; }
.begin-pair-button { margin-left: 34px; }
.release-unavailable { padding: 36px 22px; text-align: center; }
.release-unavailable strong { font-size: 14px; }
.release-unavailable p { margin: 8px auto 18px; color: var(--muted); font-size: 12px; }
@media (max-width: 600px) { .selector-grid, .setup-form { grid-template-columns: 1fr; } .asset-row { align-items: stretch; flex-direction: column; } .asset-row code { white-space: normal; overflow-wrap: anywhere; } }
</style>
