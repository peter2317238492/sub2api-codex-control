import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import NewThreadDialog from "@/components/NewThreadDialog.vue";

describe("NewThreadDialog", () => {
  it("disables submission and editing while a thread is being created", async () => {
    const wrapper = mount(NewThreadDialog, {
      props: {
        open: true,
        roots: ["/work"],
        models: [{ id: "model", display_name: "Model" }],
        submitting: true,
      },
    });

    expect(wrapper.get("button[type='submit']").attributes("disabled")).toBeDefined();
    expect(wrapper.get("button[type='submit']").attributes("aria-busy")).toBe("true");
    expect(wrapper.get("button[type='submit']").text()).toBe("创建中…");
    expect(wrapper.get("select").attributes("disabled")).toBeDefined();

    await wrapper.get("form").trigger("submit");
    expect(wrapper.emitted("create")).toBeUndefined();
  });
});
