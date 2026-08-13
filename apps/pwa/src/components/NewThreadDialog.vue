<script setup lang="ts">
import { FolderOpen, X } from "@lucide/vue";
import { ref, watch } from "vue";

import type { ModelOption } from "@/types";

const props = defineProps<{
  open: boolean;
  roots: string[];
  models: ModelOption[];
  submitting: boolean;
}>();

const emit = defineEmits<{
  close: [];
  create: [cwd: string, model?: string];
}>();

const cwd = ref("");
const model = ref("");

watch(
  () => props.open,
  (open) => {
    if (open) {
      cwd.value = props.roots[0] ?? "";
      model.value = "";
    }
  },
);

function submit(): void {
  if (!cwd.value || props.submitting) return;
  emit("create", cwd.value, model.value || undefined);
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
    <form class="dialog new-thread-dialog" @submit.prevent="submit">
      <header>
        <div>
          <span class="eyebrow">线程</span>
          <h2>新建线程</h2>
        </div>
        <button class="icon-button" type="button" title="关闭" :disabled="submitting" @click="$emit('close')"><X :size="19" /></button>
      </header>

      <label class="field-label">
        <span>工作目录</span>
        <span class="select-field"><FolderOpen :size="16" /><select v-model="cwd" required :disabled="submitting"><option v-for="root in roots" :key="root" :value="root">{{ root }}</option></select></span>
      </label>
      <label class="field-label">
        <span>模型</span>
        <select v-model="model" class="standalone-select" :disabled="submitting">
          <option value="">使用设备默认模型</option>
          <option v-for="item in models" :key="item.id" :value="item.id">{{ item.display_name }}</option>
        </select>
      </label>

      <footer>
        <button class="secondary-button" type="button" :disabled="submitting" @click="$emit('close')">取消</button>
        <button class="primary-button" type="submit" :disabled="!cwd || submitting" :aria-busy="submitting">{{ submitting ? "创建中…" : "创建" }}</button>
      </footer>
    </form>
  </div>
</template>
