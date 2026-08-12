<script setup lang="ts">
import { AlertCircle, ArrowLeft, LoaderCircle, RefreshCw } from "@lucide/vue";
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import { ApiError, onControlAuthenticationRequired } from "@/api/client";
import AppHeader from "@/components/AppHeader.vue";
import ApprovalDrawer from "@/components/ApprovalDrawer.vue";
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
const pairOpen = ref(false);
const pairLoading = ref(false);
const pairError = ref<string | null>(null);
const newThreadOpen = ref(false);
const mobilePanel = ref<"devices" | "threads" | null>(null);
const threadList = ref<{ focusAfterArchive: () => void } | null>(null);
let initialLoadComplete = false;
let bootstrapGeneration = 0;
let bootstrapPromise: Promise<boolean> | null = null;
let bootstrapSessionId: string | null = null;
let authenticationRecoveryPromise: Promise<boolean> | null = null;

function invalidateControlState(): void {
  bootstrapGeneration += 1;
  bootstrapPromise = null;
  bootstrapSessionId = null;
  authenticationRecoveryPromise = null;
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

async function claimPairing(code: string): Promise<void> {
  pairLoading.value = true;
  pairError.value = null;
  try {
    const deviceId = await controlStore.claimPairing(code);
    if (!deviceId) return;
    pairOpen.value = false;
    await bootstrapControl(true);
    if (sessionStore.authenticated && controlStore.devices.some((device) => device.id === deviceId)) {
      await controlStore.selectDevice(deviceId);
    }
  } catch (error) {
    pairError.value = error instanceof Error ? error.message : "认领失败";
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
      @pair="pairOpen = true"
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
    <PairDeviceDialog
      :open="pairOpen"
      :loading="pairLoading"
      :error="pairError"
      @close="pairOpen = false"
      @claim="claimPairing"
    />
    <NewThreadDialog
      :open="newThreadOpen"
      :roots="controlStore.selectedDevice?.workspace_roots ?? []"
      :models="controlStore.models"
      @close="newThreadOpen = false"
      @create="createThread"
    />
  </div>
</template>
