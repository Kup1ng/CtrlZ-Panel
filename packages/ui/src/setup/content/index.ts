// GENERATED from the step data of the guide (spec p3 8.3): one lazy chunk per platform and language, so the wizard of one platform
// is the only step text a page loads. Add a platform here and in platforms.ts; guide.test.ts keeps both languages and the list in step.
import type {Guide} from "../guide.ts";

type Loader = () => Promise<{default: Guide}>;

export const GUIDE_LOADERS: Record<"fa" | "en", Record<string, Loader>> = {
  fa: {
    "windows": () => import("./fa/windows.json") as unknown as Promise<{default: Guide}>,
    "mac": () => import("./fa/mac.json") as unknown as Promise<{default: Guide}>,
    "linux": () => import("./fa/linux.json") as unknown as Promise<{default: Guide}>,
    "ios": () => import("./fa/ios.json") as unknown as Promise<{default: Guide}>,
    "android": () => import("./fa/android.json") as unknown as Promise<{default: Guide}>,
    "chrome": () => import("./fa/chrome.json") as unknown as Promise<{default: Guide}>,
    "edge": () => import("./fa/edge.json") as unknown as Promise<{default: Guide}>,
    "brave": () => import("./fa/brave.json") as unknown as Promise<{default: Guide}>,
    "firefox": () => import("./fa/firefox.json") as unknown as Promise<{default: Guide}>,
    "apple-tv": () => import("./fa/apple-tv.json") as unknown as Promise<{default: Guide}>,
    "android-tv": () => import("./fa/android-tv.json") as unknown as Promise<{default: Guide}>,
    "fire-tv": () => import("./fa/fire-tv.json") as unknown as Promise<{default: Guide}>,
    "samsung-tv": () => import("./fa/samsung-tv.json") as unknown as Promise<{default: Guide}>,
    "router": () => import("./fa/router.json") as unknown as Promise<{default: Guide}>,
  },
  en: {
    "windows": () => import("./en/windows.json") as unknown as Promise<{default: Guide}>,
    "mac": () => import("./en/mac.json") as unknown as Promise<{default: Guide}>,
    "linux": () => import("./en/linux.json") as unknown as Promise<{default: Guide}>,
    "ios": () => import("./en/ios.json") as unknown as Promise<{default: Guide}>,
    "android": () => import("./en/android.json") as unknown as Promise<{default: Guide}>,
    "chrome": () => import("./en/chrome.json") as unknown as Promise<{default: Guide}>,
    "edge": () => import("./en/edge.json") as unknown as Promise<{default: Guide}>,
    "brave": () => import("./en/brave.json") as unknown as Promise<{default: Guide}>,
    "firefox": () => import("./en/firefox.json") as unknown as Promise<{default: Guide}>,
    "apple-tv": () => import("./en/apple-tv.json") as unknown as Promise<{default: Guide}>,
    "android-tv": () => import("./en/android-tv.json") as unknown as Promise<{default: Guide}>,
    "fire-tv": () => import("./en/fire-tv.json") as unknown as Promise<{default: Guide}>,
    "samsung-tv": () => import("./en/samsung-tv.json") as unknown as Promise<{default: Guide}>,
    "router": () => import("./en/router.json") as unknown as Promise<{default: Guide}>,
  },
};
