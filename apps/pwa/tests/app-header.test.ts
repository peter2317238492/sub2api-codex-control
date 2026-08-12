import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import AppHeader from "@/components/AppHeader.vue";

describe("AppHeader", () => {
  it("renders a username-less Sub2API identity without throwing", () => {
    const wrapper = mount(AppHeader, {
      props: {
        session: {
          id: "session-1",
          user: {
            id: "user-42",
            username: null,
            email: null,
            display_name: null,
          },
          issued_at: "2026-07-13T10:00:00Z",
          expires_at: "2026-07-13T10:10:00Z",
          reauth_at: "2026-07-13T10:10:00Z",
          csrf_header_name: "x-csrf-token",
        },
        live: "offline",
        pendingApprovals: 0,
        busy: false,
      },
    });

    expect(wrapper.get(".account-copy strong").text()).toBe("user-42");
    expect(wrapper.get(".avatar").text()).toBe("U");
  });
});
