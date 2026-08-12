<script setup lang="ts">
import { CircleStop, CornerDownLeft, LoaderCircle, RotateCcw, SendHorizontal, TerminalSquare } from "@lucide/vue";
import { computed, nextTick, ref, watch } from "vue";

import type { ThreadDetail } from "@/types";

const props = defineProps<{
  thread: ThreadDetail | null;
  deviceOnline: boolean;
  submitting: boolean;
  resuming: boolean;
}>();

const emit = defineEmits<{
  send: [text: string];
  steer: [text: string];
  interrupt: [];
  resume: [];
}>();

const draft = ref("");
const scrollArea = ref<HTMLElement | null>(null);
const running = computed(() => props.thread?.status === "running" || props.thread?.status === "waiting_for_approval");
const failed = computed(() => props.thread?.status === "failed");
const composerDisabled = computed(() => !props.deviceOnline || props.submitting || props.resuming || failed.value);
const blockedReason = computed(() => {
  if (!props.deviceOnline) return "设备离线";
  if (failed.value) return props.resuming ? "正在恢复线程" : "线程需要恢复";
  return null;
});

watch(
  () => props.thread?.messages.length,
  async () => {
    await nextTick();
    scrollArea.value?.scrollTo({ top: scrollArea.value.scrollHeight, behavior: "smooth" });
  },
);

async function submit(): Promise<void> {
  const text = draft.value.trim();
  if (!text || !props.thread || composerDisabled.value) return;
  draft.value = "";
  if (running.value) emit("steer", text);
  else emit("send", text);
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    void submit();
  }
}
</script>

<template>
  <main class="conversation-pane">
    <template v-if="thread">
      <header class="conversation-header">
        <div>
          <h1>{{ thread.title || "未命名线程" }}</h1>
          <span>{{ thread.cwd }}</span>
        </div>
        <div class="conversation-state">
          <span class="model-chip">{{ thread.model }}</span>
          <button
            v-if="failed"
            class="icon-button recovery-icon-button"
            type="button"
            :title="resuming ? '正在恢复线程' : deviceOnline ? '恢复线程' : '设备离线，无法恢复'"
            aria-label="恢复线程"
            :aria-busy="resuming"
            :disabled="!deviceOnline || resuming"
            @click="$emit('resume')"
          >
            <LoaderCircle v-if="resuming" class="spin" :size="17" />
            <RotateCcw v-else :size="17" />
          </button>
          <button v-if="running" class="danger-icon-button" type="button" title="中断" @click="$emit('interrupt')">
            <CircleStop :size="18" />
          </button>
        </div>
      </header>

      <section ref="scrollArea" class="message-stream" aria-live="polite">
        <article v-for="message in thread.messages" :key="message.id" class="message" :data-role="message.role">
          <div class="message-author">
            <span>{{ message.role === "assistant" ? "Codex" : message.role === "user" ? "你" : "系统" }}</span>
            <time>{{ new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" }).format(new Date(message.created_at)) }}</time>
          </div>
          <div class="message-body" :class="{ error: message.error }">{{ message.text }}</div>
          <LoaderCircle v-if="message.pending" class="spin message-pending" :size="15" />
        </article>
        <div v-if="thread.messages.length === 0" class="conversation-empty">
          <TerminalSquare :size="28" />
          <strong>新线程</strong>
        </div>
      </section>

      <footer class="composer-wrap">
        <div v-if="blockedReason" class="composer-blocked">{{ blockedReason }}</div>
        <div class="composer" :class="{ disabled: composerDisabled }">
          <textarea
            v-model="draft"
            rows="1"
            :disabled="composerDisabled"
            :placeholder="failed ? '线程恢复待处理' : running ? '引导当前 turn' : '向 Codex 发送消息'"
            @keydown="handleKeydown"
          ></textarea>
          <button
            class="send-button"
            type="button"
            :title="running ? '引导' : '发送'"
            :disabled="!draft.trim() || composerDisabled"
            @click="submit"
          >
            <CornerDownLeft v-if="running" :size="18" />
            <SendHorizontal v-else :size="18" />
          </button>
        </div>
      </footer>
    </template>

    <div v-else class="conversation-empty full">
      <TerminalSquare :size="32" />
      <strong>选择一个线程</strong>
    </div>
  </main>
</template>
