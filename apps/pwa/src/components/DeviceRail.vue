<script setup lang="ts">
import { CirclePlus, Laptop, MoreVertical, ServerOff, ShieldX } from "@lucide/vue";
import { ref } from "vue";

import type { DeviceSummary } from "@/types";

defineProps<{
  devices: DeviceSummary[];
  selectedId: string | null;
  loading: boolean;
}>();

const emit = defineEmits<{
  select: [deviceId: string];
  pair: [];
  revoke: [deviceId: string];
}>();

const menuFor = ref<string | null>(null);

function revoke(device: DeviceSummary): void {
  menuFor.value = null;
  emit("revoke", device.id);
}
</script>

<template>
  <aside class="device-rail" aria-label="设备">
    <div class="panel-title-row">
      <div>
        <span class="eyebrow">设备</span>
        <strong>{{ devices.length }}</strong>
      </div>
      <button class="icon-button" type="button" title="配对设备" @click="$emit('pair')">
        <CirclePlus :size="19" />
      </button>
    </div>

    <div v-if="loading" class="panel-loading">
      <span class="loading-line"></span>
      <span class="loading-line"></span>
    </div>

    <div v-else-if="devices.length === 0" class="panel-empty">
      <ServerOff :size="25" />
      <strong>暂无设备</strong>
      <button class="text-button" type="button" @click="$emit('pair')">开始配对</button>
    </div>

    <ul v-else class="device-list">
      <li v-for="device in devices" :key="device.id" class="device-item-wrap">
        <button
          class="device-item"
          :class="{ selected: selectedId === device.id }"
          type="button"
          @click="$emit('select', device.id)"
        >
          <span class="device-icon"><Laptop :size="18" /></span>
          <span class="device-copy">
            <strong>{{ device.name }}</strong>
            <small>
              <i class="status-dot" :data-status="device.status"></i>
              {{ device.status === "online" ? "在线" : device.status === "revoked" ? "已撤销" : "离线" }}
            </small>
          </span>
        </button>
        <button
          class="icon-button item-menu"
          type="button"
          title="设备操作"
          @click="menuFor = menuFor === device.id ? null : device.id"
        >
          <MoreVertical :size="16" />
        </button>
        <div v-if="menuFor === device.id" class="context-menu">
          <button type="button" :disabled="device.status === 'revoked'" @click="revoke(device)">
            <ShieldX :size="15" />撤销设备
          </button>
        </div>
      </li>
    </ul>
  </aside>
</template>
