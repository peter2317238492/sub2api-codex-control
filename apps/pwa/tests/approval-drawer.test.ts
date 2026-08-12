import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ApprovalDrawer from "@/components/ApprovalDrawer.vue";

describe("ApprovalDrawer", () => {
  it("disables both decisions while an approval request is in flight", () => {
    const wrapper = mount(ApprovalDrawer, {
      props: {
        open: true,
        approvals: [
          {
            approval_id: "approval-1",
            command_id: "command-1",
            kind: "command",
            summary: "Run command",
            details: {},
            expires_at: "2026-07-13T00:02:00Z",
            device_id: "device-1",
            device_name: "Device",
            created_at: "2026-07-13T00:00:00Z",
          },
        ],
        decidingApprovalIds: ["approval-1"],
      },
    });

    const buttons = wrapper.findAll(".approval-actions button");
    expect(buttons).toHaveLength(2);
    expect(buttons.every((button) => button.attributes("disabled") !== undefined)).toBe(true);
  });
});
