import { beforeEach, describe, expect, it } from "vitest";

import { readSub2ApiAccessToken } from "@/api/token";
import { MemoryStorage } from "./storage";

describe("Sub2API access token discovery", () => {
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
  });

  it("reads a direct access token", () => {
    storage.setItem("auth_token", "access-value");
    expect(readSub2ApiAccessToken(storage)).toBe("access-value");
  });

  it("does not probe legacy or generic token keys", () => {
    storage.setItem("access_token", "legacy-access-value");
    storage.setItem("token", "generic-value");
    expect(readSub2ApiAccessToken(storage)).toBeNull();
  });

  it("does not read refresh tokens or structured auth objects", () => {
    storage.setItem("refresh_token", "refresh-only");
    storage.setItem("auth_token", JSON.stringify({ access_token: "nested", refresh_token: "refresh-only" }));
    expect(readSub2ApiAccessToken(storage)).toBeNull();
  });
});
