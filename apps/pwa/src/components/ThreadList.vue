<script setup lang="ts">
import { Archive, CirclePlus, FolderOpen, LoaderCircle, MessageSquare, Search } from "@lucide/vue";
import { computed, ref } from "vue";

import type { ManagedThreadSummary } from "@/types";

const props = defineProps<{
  threads: ManagedThreadSummary[];
  selectedId: string | null;
  deviceOnline: boolean;
  archivingIds: string[];
}>();

defineEmits<{
  select: [threadId: string];
  create: [];
  archive: [threadId: string];
}>();

const query = ref("");
const panel = ref<HTMLElement | null>(null);
const filteredThreads = computed(() => {
  const needle = query.value.trim().toLocaleLowerCase();
  if (!needle) return props.threads;
  return props.threads.filter((thread) =>
    [thread.title, thread.cwd, thread.model].some((value) => value.toLocaleLowerCase().includes(needle)),
  );
});

function relativeTime(value: string): string {
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "刚刚";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时`;
  return new Intl.DateTimeFormat("zh-CN", { month: "numeric", day: "numeric" }).format(new Date(value));
}

function canArchive(thread: ManagedThreadSummary): boolean {
  return thread.status === "idle" || thread.status === "failed";
}

function archiveTitle(thread: ManagedThreadSummary): string {
  if (props.archivingIds.includes(thread.id)) return "正在归档线程";
  return canArchive(thread) ? "归档线程" : "有进行中操作，无法归档";
}

function archiveAriaLabel(thread: ManagedThreadSummary): string {
  const title = thread.title || "未命名线程";
  if (props.archivingIds.includes(thread.id)) return `正在归档线程 ${title}`;
  return canArchive(thread) ? `归档线程 ${title}` : `无法归档线程 ${title}：有进行中的操作`;
}

function focusAfterArchive(): void {
  const target =
    panel.value?.querySelector<HTMLElement>(".thread-item.selected") ??
    panel.value?.querySelector<HTMLElement>(".panel-title-row .icon-button:not(:disabled)") ??
    panel.value?.querySelector<HTMLElement>(".search-field input");
  target?.focus();
}

defineExpose({ focusAfterArchive });
</script>

<template>
  <aside ref="panel" class="thread-list-panel" aria-label="线程">
    <div class="panel-title-row">
      <div>
        <span class="eyebrow">线程</span>
        <strong>{{ threads.length }}</strong>
      </div>
      <button class="icon-button" type="button" title="新建线程" :disabled="!deviceOnline" @click="$emit('create')">
        <CirclePlus :size="19" />
      </button>
    </div>

    <label class="search-field">
      <Search :size="15" />
      <input v-model="query" type="search" placeholder="搜索线程" />
    </label>

    <div v-if="!deviceOnline" class="inline-notice">设备离线，显示最近同步内容</div>

    <div v-if="filteredThreads.length === 0" class="panel-empty compact">
      <MessageSquare :size="24" />
      <strong>{{ query ? "没有匹配项" : "暂无线程" }}</strong>
    </div>

    <ul v-else class="thread-list">
      <li v-for="thread in filteredThreads" :key="thread.id" class="thread-item-wrap">
        <button
          class="thread-item"
          :class="{ selected: selectedId === thread.id }"
          type="button"
          @click="$emit('select', thread.id)"
        >
          <span class="thread-title-row">
            <strong>{{ thread.title || "未命名线程" }}</strong>
            <i class="thread-state" :data-status="thread.status"></i>
          </span>
          <span class="thread-meta"><FolderOpen :size="13" />{{ thread.cwd }}</span>
          <span class="thread-footer"><span>{{ thread.model }}</span><time>{{ relativeTime(thread.updated_at) }}</time></span>
        </button>
        <button
          class="icon-button thread-archive-button"
          type="button"
          :title="archiveTitle(thread)"
          :aria-label="archiveAriaLabel(thread)"
          :aria-busy="archivingIds.includes(thread.id)"
          :disabled="archivingIds.includes(thread.id) || !canArchive(thread)"
          @click.stop="$emit('archive', thread.id)"
        >
          <LoaderCircle v-if="archivingIds.includes(thread.id)" class="spin" :size="15" />
          <Archive v-else :size="15" />
        </button>
      </li>
    </ul>
  </aside>
</template>
