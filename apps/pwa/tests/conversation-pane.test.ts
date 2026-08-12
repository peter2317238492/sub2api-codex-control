import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ConversationPane from "@/components/ConversationPane.vue";
import type { ThreadDetail } from "@/types";

const failedThread: ThreadDetail = {
  id: "thread-1",
  device_id: "device-1",
  title: "Needs recovery",
  cwd: "/work",
  model: "model",
  updated_at: "2026-07-30T00:00:00Z",
  status: "failed",
  messages: [],
};

describe("ConversationPane thread recovery", () => {
  it("offers recovery and keeps the composer locked for a failed thread", async () => {
    const wrapper = mount(ConversationPane, {
      props: { thread: failedThread, deviceOnline: true, submitting: false, resuming: false },
    });

    const recovery = wrapper.get(".recovery-icon-button");
    expect(recovery.attributes("title")).toBe("恢复线程");
    expect(wrapper.get(".composer-blocked").text()).toBe("线程需要恢复");
    expect(wrapper.get("textarea").attributes("disabled")).toBeDefined();
    expect(wrapper.get(".send-button").attributes("disabled")).toBeDefined();

    await wrapper.get("textarea").trigger("keydown", { key: "Enter" });
    expect(wrapper.emitted("send")).toBeUndefined();
    await recovery.trigger("click");
    expect(wrapper.emitted("resume")).toEqual([[]]);
  });

  it("shows a fixed busy recovery action and unlocks only after the thread is healthy", async () => {
    const wrapper = mount(ConversationPane, {
      props: { thread: failedThread, deviceOnline: true, submitting: false, resuming: true },
    });

    const recovery = wrapper.get(".recovery-icon-button");
    expect(recovery.attributes("disabled")).toBeDefined();
    expect(recovery.attributes("aria-busy")).toBe("true");
    expect(recovery.find(".spin").exists()).toBe(true);
    expect(wrapper.get(".composer-blocked").text()).toBe("正在恢复线程");

    await wrapper.setProps({ thread: { ...failedThread, status: "idle" }, resuming: false });
    expect(wrapper.find(".recovery-icon-button").exists()).toBe(false);
    expect(wrapper.find(".composer-blocked").exists()).toBe(false);
    expect(wrapper.get("textarea").attributes("disabled")).toBeUndefined();
  });
});
