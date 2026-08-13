import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import ApprovalDrawer from "@/components/ApprovalDrawer.vue";

describe("ApprovalDrawer", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

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
            expires_at: "2099-07-13T00:02:00Z",
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

  it("disables an approval as soon as it expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T00:00:00Z"));
    const wrapper = mount(ApprovalDrawer, {
      props: {
        open: true,
        approvals: [
          {
            approval_id: "approval-expiring",
            command_id: "command-1",
            kind: "permission",
            summary: "Grant permission",
            details: {},
            expires_at: "2026-07-13T00:00:01Z",
            device_id: "device-1",
            device_name: "Device",
            created_at: "2026-07-13T00:00:00Z",
          },
        ],
        decidingApprovalIds: [],
      },
    });

    expect(wrapper.findAll(".approval-actions button").every((button) => !button.attributes("disabled"))).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(wrapper.text()).toContain("已过期");
    const buttons = wrapper.findAll(".approval-actions button");
    expect(buttons.every((button) => button.attributes("disabled") !== undefined)).toBe(true);
    await buttons[1]?.trigger("click");
    expect(wrapper.emitted("decide")).toBeUndefined();
  });
});
