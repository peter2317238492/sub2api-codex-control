import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ThreadList from "@/components/ThreadList.vue";
import type { ManagedThreadSummary } from "@/types";

const threads: ManagedThreadSummary[] = [
  {
    id: "idle-thread",
    device_id: "device-1",
    title: "Ready to archive",
    cwd: "/work",
    model: "model",
    updated_at: "2026-07-30T00:00:00Z",
    status: "idle",
  },
  {
    id: "running-thread",
    device_id: "device-1",
    title: "Still running",
    cwd: "/work",
    model: "model",
    updated_at: "2026-07-30T00:00:00Z",
    status: "running",
  },
];

describe("ThreadList archive controls", () => {
  it("emits archive only for a safely idle thread", async () => {
    const wrapper = mount(ThreadList, {
      props: { threads, selectedId: "idle-thread", deviceOnline: true, archivingIds: [] },
    });
    const buttons = wrapper.findAll(".thread-archive-button");

    expect(buttons[0]?.attributes("title")).toBe("归档线程");
    expect(buttons[0]?.attributes("aria-label")).toBe("归档线程 Ready to archive");
    expect(buttons[1]?.attributes("disabled")).toBeDefined();
    expect(buttons[1]?.attributes("title")).toBe("有进行中操作，无法归档");
    expect(buttons[1]?.attributes("aria-label")).toBe("无法归档线程 Still running：有进行中的操作");

    await buttons[0]?.trigger("click");
    expect(wrapper.emitted("archive")).toEqual([["idle-thread"]]);
  });

  it("shows a busy, disabled archive action while the request is pending", () => {
    const wrapper = mount(ThreadList, {
      props: { threads: [threads[0]!], selectedId: null, deviceOnline: false, archivingIds: ["idle-thread"] },
    });
    const button = wrapper.get(".thread-archive-button");

    expect(button.attributes("disabled")).toBeDefined();
    expect(button.attributes("aria-busy")).toBe("true");
    expect(button.attributes("title")).toBe("正在归档线程");
    expect(button.find(".spin").exists()).toBe(true);
    expect(button.attributes("aria-label")).toBe("正在归档线程 Ready to archive");
  });

  it("restores focus to the selected replacement or the create action", async () => {
    const wrapper = mount(ThreadList, {
      attachTo: document.body,
      props: { threads, selectedId: "running-thread", deviceOnline: true, archivingIds: [] },
    });
    (wrapper.get(".thread-archive-button").element as HTMLElement).focus();
    await wrapper.setProps({ threads: [threads[1]!] });
    wrapper.vm.focusAfterArchive();
    expect(document.activeElement).toBe(wrapper.get(".thread-item.selected").element);

    await wrapper.setProps({ threads: [], selectedId: null });
    wrapper.vm.focusAfterArchive();
    expect(document.activeElement).toBe(wrapper.get(".panel-title-row .icon-button").element);
    wrapper.unmount();
  });
});
