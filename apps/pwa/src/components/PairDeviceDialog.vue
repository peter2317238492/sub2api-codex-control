<script setup lang="ts">
import { KeyRound, LoaderCircle, X } from "@lucide/vue";
import { computed, ref, watch } from "vue";

const props = defineProps<{
  open: boolean;
  loading: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  close: [];
  claim: [code: string];
}>();

const code = ref("");
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

      <label class="pair-code-field">
        <span class="sr-only">配对码</span>
        <KeyRound :size="20" />
        <input
          :value="code"
          inputmode="text"
          autocomplete="one-time-code"
          maxlength="19"
          placeholder="XXXX-XXXX-XXXX-XXXX"
          autofocus
          @input="updateCode"
        />
      </label>
      <p v-if="error" class="form-error">{{ error }}</p>
      <footer>
        <button class="secondary-button" type="button" @click="$emit('close')">取消</button>
        <button class="primary-button" type="submit" :disabled="loading || !canonicalCode">
          <LoaderCircle v-if="loading" class="spin" :size="17" />
          认领设备
        </button>
      </footer>
    </form>
  </div>
</template>
