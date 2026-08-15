<script setup lang="ts">
import { AlertCircle, ArrowLeft, LoaderCircle, RefreshCw } from "@lucide/vue";
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import { ApiError, onControlAuthenticationRequired } from "@/api/client";
import AppHeader from "@/components/AppHeader.vue";
import ApprovalDrawer from "@/components/ApprovalDrawer.vue";
import ConnectorSetupDialog from "@/components/ConnectorSetupDialog.vue";
import ConversationPane from "@/components/ConversationPane.vue";
import DeviceRail from "@/components/DeviceRail.vue";
import NewThreadDialog from "@/components/NewThreadDialog.vue";
import PairDeviceDialog from "@/components/PairDeviceDialog.vue";
import ThreadList from "@/components/ThreadList.vue";
import { useControlStore } from "@/stores/control";
import { useSessionStore } from "@/stores/session";

const sessionStore = useSessionStore();
const controlStore = useControlStore();

const approvalOpen = ref(false);
const connectorSetupOpen = ref(false);
const pairOpen = ref(false);
const pairLoading = ref(false);
const pairCompleting = ref(false);
const pairError = ref<string | null>(null);
const pairRecovery = ref<"new_code" | "retry" | "manage_devices" | null>(null);
const pendingPairingDeviceId = ref<string | null>(null);
const pendingPairingDeviceSeen = ref(false);
const newThreadOpen = ref(false);
const mobilePanel = ref<"devices" | "threads" | null>(null);
const threadList = ref<{ focusAfterArchive: () => void } | null>(null);
let initialLoadComplete = false;
let bootstrapGeneration = 0;
let bootstrapPromise: Promise<boolean> | null = null;
let bootstrapSessionId: string | null = null;
let authenticationRecoveryPromise: Promise<boolean> | null = null;
let pairingCompletionPromise: Promise<boolean> | null = null;

function resetPairingState(close = false): void {
  pendingPairingDeviceId.value = null;
  pendingPairingDeviceSeen.value = false;
  pairLoading.value = false;
  pairCompleting.value = false;
  pairError.value = null;
  pairRecovery.value = null;
  pairingCompletionPromise = null;
  if (close) pairOpen.value = false;
}

function invalidateControlState(): void {
  bootstrapGeneration += 1;
  bootstrapPromise = null;
  bootstrapSessionId = null;
  authenticationRecoveryPromise = null;
  resetPairingState(true);
  controlStore.reset();
}

function bootstrapControl(force = false): Promise<boolean> {
  if (!sessionStore.authenticated) return Promise.resolve(false);
  if (bootstrapPromise) {
    const activeBootstrap = bootstrapPromise;
    return force ? activeBootstrap.then(() => bootstrapControl()) : activeBootstrap;
  }
  const generation = bootstrapGeneration;
  const targetSessionId = sessionStore.session?.id ?? null;
  const currentPromise = controlStore.bootstrap().finally(() => {
    if (generation === bootstrapGeneration && bootstrapPromise === currentPromise) {
      bootstrapPromise = null;
      bootstrapSessionId = null;
    }
  });
  bootstrapPromise = currentPromise;
  bootstrapSessionId = targetSessionId;
  return currentPromise;
}

function bootstrapAfterRenewal(): Promise<boolean> {
  if (bootstrapPromise && bootstrapSessionId === (sessionStore.session?.id ?? null)) return bootstrapPromise;
  return bootstrapControl(true);
}

function recoverControlAuthentication(): Promise<boolean> {
  controlStore.disconnectEvents();
  if (!sessionStore.authenticated) return Promise.resolve(false);
  if (authenticationRecoveryPromise) return authenticationRecoveryPromise;
  const principalId = sessionStore.session?.user.id;
  const currentPromise = sessionStore.handleAuthenticationFailure().then(
    (recovered) => recovered && sessionStore.session?.user.id === principalId,
  ).finally(() => {
    if (authenticationRecoveryPromise === currentPromise) authenticationRecoveryPromise = null;
  });
  authenticationRecoveryPromise = currentPromise;
  return currentPromise;
}

const stopAuthenticationListener = onControlAuthenticationRequired(() => {
  return recoverControlAuthentication();
});

const stopAuthenticationWatch = watch(
  () => sessionStore.authenticated,
  (authenticated) => {
    if (!authenticated) {
      invalidateControlState();
    } else if (initialLoadComplete) {
      void bootstrapControl();
    }
  },
  { flush: "sync" },
);

const stopPrincipalWatch = watch(
  () => sessionStore.session?.user.id ?? null,
  (userId, previousUserId) => {
    if (previousUserId !== null && userId !== previousUserId) invalidateControlState();
  },
  { flush: "sync" },
);

const stopRenewalWatch = watch(
  () => sessionStore.renewalRevision,
  () => {
    if (initialLoadComplete && sessionStore.authenticated) void bootstrapAfterRenewal();
  },
  { flush: "sync" },
);

const stopExternalAuthWatch = watch(
  () => sessionStore.externalAuthRevision,
  () => {
    if (initialLoadComplete) invalidateControlState();
  },
  { flush: "sync" },
);

const stopPairingDeviceWatch = watch(
  () => {
    const deviceId = pendingPairingDeviceId.value;
    if (!deviceId) return null;
    const device = controlStore.devices.find((item) => item.id === deviceId);
    return device ? `${device.id}:${device.status}` : null;
  },
  (deviceState) => {
    if (deviceState) pendingPairingDeviceSeen.value = true;
    void completePendingPairing();
  },
  { flush: "post" },
);

onMounted(async () => {
  await sessionStore.load();
  initialLoadComplete = true;
  if (sessionStore.authenticated) await bootstrapControl();
});

onBeforeUnmount(() => {
  initialLoadComplete = false;
  stopAuthenticationListener();
  stopAuthenticationWatch();
  stopPrincipalWatch();
  stopRenewalWatch();
  stopExternalAuthWatch();
  stopPairingDeviceWatch();
  invalidateControlState();
  sessionStore.dispose();
});

async function refresh(): Promise<void> {
  if (sessionStore.authenticated) {
    const renewed = await sessionStore.renew();
    if (renewed && sessionStore.authenticated) {
      await bootstrapAfterRenewal();
      await controlStore.syncSelection(true);
    }
  } else await sessionStore.load();
}

async function logout(): Promise<void> {
  invalidateControlState();
  await sessionStore.logout();
}

async function selectDevice(deviceId: string): Promise<void> {
  try {
    await controlStore.selectDevice(deviceId);
    mobilePanel.value = "threads";
  } catch (error) {
    reportControlError(error);
  }
}

async function selectThread(threadId: string): Promise<void> {
  try {
    await controlStore.selectThread(threadId);
    mobilePanel.value = null;
  } catch (error) {
    reportControlError(error);
  }
}

function openPairing(): void {
  if (!pendingPairingDeviceId.value) {
    pairError.value = null;
    pairRecovery.value = null;
  }
  pairOpen.value = true;
}

function restartPairing(): void {
  resetPairingState();
  pairOpen.value = true;
}

function pairFromSetup(): void {
  connectorSetupOpen.value = false;
  restartPairing();
}

function managePairingDevices(): void {
  pairOpen.value = false;
  mobilePanel.value = "devices";
}

function pairingErrorPresentation(error: unknown): {
  message: string;
  recovery: "new_code" | "retry" | "manage_devices";
} {
  if (error instanceof ApiError) {
    const code = error.code ?? error.message;
    if (code === "pairing_not_found") {
      return {
        message: "未找到这个配对码。请确认输入无误，或在设备上重新开始配对后输入新配对码。",
        recovery: "new_code",
      };
    }
    if (code === "pairing_expired" || error.status === 410) {
      return {
        message: "配对码已过期。请在设备上重新开始 Connector 配对，然后输入新配对码。",
        recovery: "new_code",
      };
    }
    if (code === "pairing_not_claimable") {
      return {
        message: "这个配对码已被认领或不再可用。请在设备上重新开始配对并输入新配对码。",
        recovery: "new_code",
      };
    }
    if (code === "device_capacity_exceeded") {
      return {
        message: "设备数量已达上限。请先撤销不再使用的设备，然后重试。",
        recovery: "manage_devices",
      };
    }
    if (code === "pairing_claim_rate_limited" || error.status === 429) {
      return { message: "配对尝试次数过多，请稍后再试。", recovery: "retry" };
    }
    if (error.status === 404) {
      return { message: "未找到这个配对码，请检查后重试。", recovery: "new_code" };
    }
    if (error.status === 409) {
      return { message: "这个配对码当前不可用，请获取新配对码后重试。", recovery: "new_code" };
    }
  }
  return { message: "暂时无法认领设备，请检查网络后重试。", recovery: "retry" };
}

function completePendingPairing(): Promise<boolean> {
  if (pairingCompletionPromise) return pairingCompletionPromise;
  const pendingDeviceId = pendingPairingDeviceId.value;
  if (!pendingDeviceId) return Promise.resolve(false);
  const device = controlStore.devices.find((item) => item.id === pendingDeviceId);
  if (!device || device.status !== "online") return Promise.resolve(false);

  pendingPairingDeviceSeen.value = true;
  pairCompleting.value = true;
  const currentPromise = (async () => {
    try {
      await controlStore.selectDevice(pendingDeviceId);
      if (pendingPairingDeviceId.value !== pendingDeviceId) return false;
      if (controlStore.selectedDeviceId !== pendingDeviceId) {
        pairError.value = "设备已上线，但设备信息仍在同步。请刷新状态后重试。";
        pairRecovery.value = "retry";
        return false;
      }
      pendingPairingDeviceId.value = null;
      pendingPairingDeviceSeen.value = false;
      pairError.value = null;
      pairRecovery.value = null;
      pairOpen.value = false;
      mobilePanel.value = "threads";
      return true;
    } catch {
      if (pendingPairingDeviceId.value === pendingDeviceId) {
        pairError.value = "设备已上线，但暂时无法加载设备信息。请刷新状态后重试。";
        pairRecovery.value = "retry";
      }
      return false;
    } finally {
      pairCompleting.value = false;
    }
  })().finally(() => {
    if (pairingCompletionPromise === currentPromise) pairingCompletionPromise = null;
  });
  pairingCompletionPromise = currentPromise;
  return currentPromise;
}

async function claimPairing(code: string): Promise<void> {
  pairLoading.value = true;
  pairError.value = null;
  pairRecovery.value = null;
  try {
    const deviceId = await controlStore.claimPairing(code);
    if (!deviceId) return;
    pendingPairingDeviceId.value = deviceId;
    pendingPairingDeviceSeen.value = controlStore.devices.some((device) => device.id === deviceId);
    const refreshed = await bootstrapControl(true);
    if (!refreshed && pendingPairingDeviceId.value === deviceId) {
      pairError.value = "配对码已认领，但暂时无法刷新设备状态。Connector 可继续完成配对，请稍后刷新。";
      pairRecovery.value = "retry";
    }
  } catch (error) {
    const presentation = pairingErrorPresentation(error);
    pairError.value = presentation.message;
    pairRecovery.value = presentation.recovery;
  } finally {
    pairLoading.value = false;
  }
}

async function refreshPairingStatus(): Promise<void> {
  if (!pendingPairingDeviceId.value || pairLoading.value || pairCompleting.value) return;
  pairLoading.value = true;
  pairError.value = null;
  pairRecovery.value = null;
  try {
    const refreshed = await bootstrapControl(true);
    if (!refreshed && pendingPairingDeviceId.value) {
      pairError.value = "暂时无法刷新设备状态，请检查网络后重试。";
      pairRecovery.value = "retry";
    }
  } finally {
    pairLoading.value = false;
  }
}

async function createThread(cwd: string, model?: string): Promise<void> {
  try {
    const created = await controlStore.createThread(cwd, model);
    if (created) {
      newThreadOpen.value = false;
      mobilePanel.value = null;
    }
  } catch (error) {
    reportControlError(error);
  }
}

async function archiveThread(threadId: string): Promise<void> {
  const thread = controlStore.threads.find((item) => item.id === threadId);
  if (!thread) return;
  const title = thread.title || "未命名线程";
  if (!window.confirm(`从 Codex Control 归档线程“${title}”？设备上的 Codex 线程不会被删除。`)) return;
  try {
    const archived = await controlStore.archiveThread(threadId);
    if (archived) {
      controlStore.error = null;
      await nextTick();
      threadList.value?.focusAfterArchive();
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      controlStore.error = "线程仍有进行中的操作，暂时无法归档";
      return;
    }
    reportControlError(error);
  }
}

async function revokeDevice(deviceId: string): Promise<void> {
  const device = controlStore.devices.find((item) => item.id === deviceId);
  if (!device || !window.confirm(`撤销设备“${device.name}”？`)) return;
  try {
    await controlStore.revokeDevice(deviceId);
  } catch (error) {
    reportControlError(error);
  }
}

function reportControlError(error: unknown): void {
  controlStore.error = error instanceof Error ? error.message : "操作失败";
}

async function sendTurn(text: string): Promise<void> {
  try {
    await controlStore.sendTurn(text);
  } catch (error) {
    reportControlError(error);
  }
}

async function steerTurn(text: string): Promise<void> {
  try {
    await controlStore.steerTurn(text);
  } catch (error) {
    reportControlError(error);
  }
}

async function interruptTurn(): Promise<void> {
  try {
    await controlStore.interruptTurn();
  } catch (error) {
    reportControlError(error);
  }
}

async function resumeThread(): Promise<void> {
  try {
    await controlStore.resumeThread();
  } catch (error) {
    reportControlError(error);
  }
}

async function resolveApproval(approvalId: string, decision: "approve" | "deny"): Promise<void> {
  try {
    await controlStore.resolveApproval(approvalId, decision);
  } catch (error) {
    reportControlError(error);
  }
}
</script>

<template>
  <div v-if="sessionStore.state === 'loading'" class="session-screen">
    <div class="session-brand"><span class="brand-mark large">C<span></span></span><strong>Codex Control</strong></div>
    <LoaderCircle class="spin" :size="24" />
  </div>

  <div v-else-if="!sessionStore.authenticated" class="session-screen">
    <div class="session-gate">
      <div class="session-brand"><span class="brand-mark large">C<span></span></span><strong>Codex Control</strong></div>
      <AlertCircle v-if="sessionStore.state === 'error'" class="session-alert" :size="24" />
      <h1>{{ sessionStore.state === "expired" ? "登录已过期" : sessionStore.state === "error" ? "暂时无法连接" : "需要登录 Sub2API" }}</h1>
      <p v-if="sessionStore.error">{{ sessionStore.error }}</p>
      <div class="session-actions">
        <a class="secondary-button" href="/"><ArrowLeft :size="17" />返回 Sub2API</a>
        <button class="primary-button" type="button" :disabled="sessionStore.busy" @click="refresh">
          <RefreshCw :class="{ spin: sessionStore.busy }" :size="17" />重试
        </button>
      </div>
    </div>
  </div>

  <div v-else-if="sessionStore.session" class="app-shell" :data-mobile-panel="mobilePanel">
    <AppHeader
      :session="sessionStore.session"
      :live="controlStore.live"
      :pending-approvals="controlStore.pendingApprovals"
      :busy="sessionStore.busy || controlStore.loading"
      @refresh="refresh"
      @logout="logout"
      @approvals="approvalOpen = true"
      @devices="mobilePanel = mobilePanel === 'devices' ? null : 'devices'"
      @threads="mobilePanel = mobilePanel === 'threads' ? null : 'threads'"
    />

    <DeviceRail
      :devices="controlStore.devices"
      :selected-id="controlStore.selectedDeviceId"
      :loading="controlStore.loading"
      @select="selectDevice"
      @pair="openPairing"
      @setup="connectorSetupOpen = true"
      @revoke="revokeDevice"
    />

    <ThreadList
      ref="threadList"
      :threads="controlStore.threads"
      :selected-id="controlStore.selectedThreadId"
      :device-online="controlStore.selectedDevice?.status === 'online'"
      :archiving-ids="controlStore.archivingThreadIds"
      @select="selectThread"
      @create="newThreadOpen = true"
      @archive="archiveThread"
    />

    <ConversationPane
      :thread="controlStore.activeThread"
      :device-online="controlStore.selectedDevice?.status === 'online'"
      :submitting="controlStore.turnSubmitting"
      :resuming="controlStore.selectedThreadId ? controlStore.resumingThreadIds.includes(controlStore.selectedThreadId) : false"
      @send="sendTurn"
      @steer="steerTurn"
      @interrupt="interruptTurn"
      @resume="resumeThread"
    />

    <div v-if="mobilePanel" class="mobile-scrim" @click="mobilePanel = null"></div>

    <div v-if="controlStore.error" class="toast error-toast">
      <AlertCircle :size="17" />{{ controlStore.error }}
      <button class="icon-button" type="button" title="关闭" @click="controlStore.error = null">×</button>
    </div>

    <ApprovalDrawer
      :open="approvalOpen"
      :approvals="controlStore.approvals"
      :deciding-approval-ids="controlStore.decidingApprovalIds"
      @close="approvalOpen = false"
      @decide="resolveApproval"
    />
    <ConnectorSetupDialog
      :open="connectorSetupOpen"
      :metadata="controlStore.connectorRelease"
      @close="connectorSetupOpen = false"
      @pair="pairFromSetup"
    />
    <PairDeviceDialog
      :open="pairOpen"
      :loading="pairLoading || pairCompleting"
      :error="pairError"
      :waiting="pendingPairingDeviceId !== null"
      :device-detected="pendingPairingDeviceSeen"
      :recovery="pairRecovery"
      @close="pairOpen = false"
      @claim="claimPairing"
      @refresh="refreshPairingStatus"
      @restart="restartPairing"
      @manage="managePairingDevices"
    />
    <NewThreadDialog
      :open="newThreadOpen"
      :roots="controlStore.selectedDevice?.workspace_roots ?? []"
      :models="controlStore.models"
      :submitting="controlStore.creatingThread"
      @close="newThreadOpen = false"
      @create="createThread"
    />
  </div>
</template>
