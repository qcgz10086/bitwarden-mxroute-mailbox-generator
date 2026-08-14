import { describe, expect, it } from "vitest";
import { currentLanguage, setLanguage, t, tf } from "../../workers/admin/ui/i18n";

const store = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage = {
  getItem: (key: string) => store.get(key) ?? null,
  setItem: (key: string, value: string) => void store.set(key, value),
};

describe("admin UI i18n", () => {
  it("defaults to Chinese when no preference is stored", () => {
    store.clear();
    expect(currentLanguage()).toBe("zh");
    expect(t("navMailboxes")).toBe("邮箱");
    expect(t("appTitle")).toBe("邮箱管理后台");
  });

  it("switches to English and persists the choice", () => {
    store.clear();
    setLanguage("en");
    expect(currentLanguage()).toBe("en");
    expect(t("navMailboxes")).toBe("Mailboxes");
    expect(tf("loadedMailboxes", { count: 3 })).toBe("Loaded 3 mailboxes.");
    expect(tf("passwordShown", { email: "a@b.c" })).toContain("a@b.c");
  });

  it("falls back to the key when a translation is missing", () => {
    expect(t("no-such-key")).toBe("no-such-key");
  });
});
