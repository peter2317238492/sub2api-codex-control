import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import PairDeviceDialog from "@/components/PairDeviceDialog.vue";

describe("PairDeviceDialog", () => {
  it("formats and submits the exact canonical 16-symbol pairing code", async () => {
    const wrapper = mount(PairDeviceDialog, {
      props: { open: true, loading: false, error: null },
    });
    const input = wrapper.get("input");

    await input.setValue("23456789abcdefgh");

    expect(input.element.value).toBe("2345-6789-ABCD-EFGH");
    expect(wrapper.get('button[type="submit"]').attributes("disabled")).toBeUndefined();
    await wrapper.get("form").trigger("submit");
    expect(wrapper.emitted("claim")).toEqual([["2345-6789-ABCD-EFGH"]]);
  });

  it("does not submit an incomplete or ambiguous pairing code", async () => {
    const wrapper = mount(PairDeviceDialog, {
      props: { open: true, loading: false, error: null },
    });
    const input = wrapper.get("input");

    await input.setValue("2345-6789-I0O1");

    expect(input.element.value).toBe("2345-6789");
    expect(wrapper.get('button[type="submit"]').attributes("disabled")).toBeDefined();
    await wrapper.get("form").trigger("submit");
    expect(wrapper.emitted("claim")).toBeUndefined();
  });

  it("keeps a claimed pairing visible until the Connector comes online", async () => {
    const wrapper = mount(PairDeviceDialog, {
      props: {
        open: true,
        loading: false,
        error: null,
        waiting: true,
        deviceDetected: false,
      },
    });

    expect(wrapper.get("[role='status']").text()).toContain("配对码已认领");
    expect(wrapper.find("input").exists()).toBe(false);
    await wrapper.get(".pair-refresh-button").trigger("click");
    expect(wrapper.emitted("refresh")).toHaveLength(1);

    await wrapper.setProps({ deviceDetected: true });
    expect(wrapper.get("[role='status']").text()).toContain("设备已完成配对");
    expect(wrapper.get("[role='status']").text()).toContain("等待 Connector 上线");

    await wrapper.get(".pair-restart-button").trigger("click");
    expect(wrapper.emitted("restart")).toHaveLength(1);
  });

  it("offers the recovery action selected for a friendly pairing error", async () => {
    const wrapper = mount(PairDeviceDialog, {
      props: {
        open: true,
        loading: false,
        error: "设备数量已达上限。请先撤销不再使用的设备，然后重试。",
        recovery: "manage_devices",
      },
    });

    expect(wrapper.text()).toContain("设备数量已达上限");
    await wrapper.get(".pair-manage-button").trigger("click");
    expect(wrapper.emitted("manage")).toHaveLength(1);
  });
});
