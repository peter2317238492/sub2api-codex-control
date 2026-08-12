<script setup lang="ts">
import { Check, Clock3, LoaderCircle, ShieldAlert, X, XCircle } from "@lucide/vue";

import type { ApprovalItem } from "@/types";

const props = defineProps<{
  open: boolean;
  approvals: ApprovalItem[];
  decidingApprovalIds: string[];
}>();

function isDeciding(approvalId: string): boolean {
  return props.decidingApprovalIds.includes(approvalId);
}

defineEmits<{
  close: [];
  decide: [approvalId: string, decision: "approve" | "deny"];
}>();
</script>

<template>
  <div v-if="open" class="drawer-backdrop" @click.self="$emit('close')">
    <aside class="approval-drawer" aria-label="待审批">
      <header>
        <div>
          <span class="eyebrow">审批</span>
          <h2>待处理 {{ approvals.length }}</h2>
        </div>
        <button class="icon-button" type="button" title="关闭" @click="$emit('close')"><X :size="19" /></button>
      </header>

      <div v-if="approvals.length === 0" class="panel-empty drawer-empty">
        <Check :size="25" />
        <strong>没有待审批项</strong>
      </div>

      <ol v-else class="approval-list">
        <li v-for="approval in approvals" :key="approval.approval_id" class="approval-item">
          <div class="approval-heading">
            <span class="approval-kind"><ShieldAlert :size="16" />{{ approval.kind }}</span>
            <span class="approval-expiry"><Clock3 :size="14" />{{ new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(approval.expires_at)) }}</span>
          </div>
          <strong>{{ approval.summary }}</strong>
          <p>{{ approval.device_name }}</p>
          <pre>{{ JSON.stringify(approval.details, null, 2) }}</pre>
          <div class="approval-actions">
            <button
              class="deny-button"
              type="button"
              :disabled="isDeciding(approval.approval_id)"
              @click="$emit('decide', approval.approval_id, 'deny')"
            >
              <LoaderCircle v-if="isDeciding(approval.approval_id)" class="spin" :size="17" />
              <XCircle v-else :size="17" />拒绝
            </button>
            <button
              class="approve-button"
              type="button"
              :disabled="isDeciding(approval.approval_id)"
              @click="$emit('decide', approval.approval_id, 'approve')"
            >
              <LoaderCircle v-if="isDeciding(approval.approval_id)" class="spin" :size="17" />
              <Check v-else :size="17" />批准
            </button>
          </div>
        </li>
      </ol>
    </aside>
  </div>
</template>
