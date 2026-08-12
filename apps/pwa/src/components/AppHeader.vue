<script setup lang="ts">
import { Bell, LogOut, MonitorSmartphone, PanelLeft, RefreshCw, Wifi, WifiOff } from "@lucide/vue";
import { computed } from "vue";

import type { SessionSnapshot } from "@/types";

const props = defineProps<{
  session: SessionSnapshot;
  live: "connecting" | "online" | "offline";
  pendingApprovals: number;
  busy: boolean;
}>();

const accountName = computed(
  () =>
    props.session.user.display_name?.trim() ||
    props.session.user.username?.trim() ||
    props.session.user.email?.trim() ||
    props.session.user.id,
);
const accountInitial = computed(() => Array.from(accountName.value)[0]?.toLocaleUpperCase() ?? "U");

defineEmits<{
  refresh: [];
  logout: [];
  approvals: [];
  devices: [];
  threads: [];
}>();
</script>

<template>
  <header class="app-header">
    <div class="brand-lockup" aria-label="Codex Control">
      <span class="brand-mark">C<span></span></span>
      <div>
        <strong>Codex Control</strong>
        <small>Sub2API</small>
      </div>
    </div>

    <div class="header-mobile-nav">
      <button class="icon-button" type="button" title="设备" @click="$emit('devices')">
        <MonitorSmartphone :size="18" />
      </button>
      <button class="icon-button" type="button" title="线程" @click="$emit('threads')">
        <PanelLeft :size="18" />
      </button>
    </div>

    <div class="header-actions">
      <span class="live-state" :data-state="live">
        <Wifi v-if="live === 'online'" :size="15" />
        <RefreshCw v-else-if="live === 'connecting'" class="spin" :size="15" />
        <WifiOff v-else :size="15" />
        {{ live === "online" ? "实时" : live === "connecting" ? "连接中" : "离线" }}
      </span>

      <button class="icon-button approval-button" type="button" title="待审批" aria-label="待审批" @click="$emit('approvals')">
        <Bell :size="18" />
        <span v-if="pendingApprovals" class="badge" aria-hidden="true">{{ pendingApprovals > 99 ? "99+" : pendingApprovals }}</span>
      </button>
      <button class="icon-button" type="button" title="续期并刷新" :disabled="busy" @click="$emit('refresh')">
        <RefreshCw :class="{ spin: busy }" :size="18" />
      </button>

      <div class="account-chip">
        <span class="avatar">{{ accountInitial }}</span>
        <span class="account-copy">
          <strong>{{ accountName }}</strong>
          <small>用户</small>
        </span>
      </div>
      <button class="icon-button" type="button" title="退出控制会话" :disabled="busy" @click="$emit('logout')">
        <LogOut :size="18" />
      </button>
    </div>
  </header>
</template>
