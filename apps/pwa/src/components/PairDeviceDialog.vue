<script setup lang="ts">
import { CircleCheck, KeyRound, LoaderCircle, RefreshCw, X } from "@lucide/vue";
import { computed, nextTick, ref, watch } from "vue";

const props = defineProps<{
  open: boolean;
  loading: boolean;
  error: string | null;
  waiting?: boolean;
  deviceDetected?: boolean;
  recovery?: "new_code" | "retry" | "manage_devices" | null;
}>();

const emit = defineEmits<{
  close: [];
  claim: [code: string];
  refresh: [];
  restart: [];
  manage: [];
}>();

const code = ref("");
const codeInput = ref<HTMLInputElement | null>(null);
const pairingSymbolPattern = /[^23456789ABCDEFGHJKLMNPQRSTUVWXYZ]/g;
const canonicalCode = computed(() => {
  const symbols = code.value.replace(pairingSymbolPattern, "");
  if (symbols.length !== 16) return null;
  return symbols.match(/.{4}/g)?.join("-") ?? null;
});

watch(
  () => props.open,
  (open) => {
    if (open) code.value = "";
  },
);

function restart(): void {
  code.value = "";
  emit("restart");
  void nextTick(() => codeInput.value?.focus());
}

function submit(): void {
  if (props.loading || !canonicalCode.value) return;
  emit("claim", canonicalCode.value);
}

function updateCode(event: Event): void {
  const input = event.target as HTMLInputElement;
  const symbols = input.value.toUpperCase().replace(pairingSymbolPattern, "").slice(0, 16);
  code.value = symbols.match(/.{1,4}/g)?.join("-") ?? "";
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
    <form class="dialog pair-dialog" role="dialog" aria-modal="true" aria-labelledby="pair-title" @submit.prevent="submit">
      <header>
        <div>
          <span class="eyebrow">设备</span>
          <h2 id="pair-title">配对 Connector</h2>
        </div>
        <button class="icon-button" type="button" title="关闭" @click="$emit('close')"><X :size="19" /></button>
      </header>

      <section v-if="waiting" class="pair-waiting" role="status" aria-live="polite">
        <CircleCheck v-if="deviceDetected" class="pair-waiting-icon detected" :size="28" />
        <LoaderCircle v-else class="pair-waiting-icon spin" :size="28" />
        <strong>{{ deviceDetected ? "设备已完成配对" : "配对码已认领" }}</strong>
        <p>{{ deviceDetected ? "正在等待 Connector 上线。" : "请保持 Connector 运行，正在等待设备完成配对并上线。" }}</p>
      </section>

      <template v-else>
        <label class="pair-code-field">
          <span class="sr-only">配对码</span>
          <KeyRound :size="20" />
          <input
            ref="codeInput"
            :value="code"
            inputmode="text"
            autocomplete="one-time-code"
            maxlength="19"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            autofocus
            @input="updateCode"
          />
        </label>
      </template>
      <p v-if="error" class="form-error">{{ error }}</p>
      <footer v-if="waiting">
        <button class="secondary-button pair-restart-button" type="button" :disabled="loading" @click="restart">重新输入配对码</button>
        <button class="primary-button pair-refresh-button" type="button" :disabled="loading" @click="$emit('refresh')">
          <LoaderCircle v-if="loading" class="spin" :size="17" />
          <RefreshCw v-else :size="17" />刷新状态
        </button>
      </footer>
      <footer v-else-if="error && recovery === 'manage_devices'">
        <button class="secondary-button" type="button" @click="$emit('close')">关闭</button>
        <button class="primary-button pair-manage-button" type="button" @click="$emit('manage')">管理设备</button>
      </footer>
      <footer v-else-if="error && recovery === 'new_code'">
        <button class="secondary-button" type="button" @click="$emit('close')">取消</button>
        <button class="primary-button pair-new-code-button" type="button" @click="restart">输入新配对码</button>
      </footer>
      <footer v-else>
        <button class="secondary-button" type="button" @click="$emit('close')">取消</button>
        <button class="primary-button" type="submit" :disabled="loading || !canonicalCode">
          <LoaderCircle v-if="loading" class="spin" :size="17" />
          {{ error && recovery === "retry" ? "重试" : "认领设备" }}
        </button>
      </footer>
    </form>
  </div>
</template>

<style scoped>
.pair-waiting {
  display: flex;
  min-height: 150px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  padding: 24px 20px 16px;
  color: var(--muted);
  text-align: center;
}

.pair-waiting-icon {
  color: var(--amber);
}

.pair-waiting-icon.detected {
  color: var(--green);
}

.pair-waiting strong {
  color: var(--ink);
  font-size: 14px;
}

.pair-waiting p {
  max-width: 330px;
  margin: 0;
  font-size: 12px;
  line-height: 1.5;
}

.pair-waiting + .form-error {
  margin-top: -6px;
  padding-bottom: 8px;
  text-align: center;
}
</style>
