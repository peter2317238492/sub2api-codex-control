import { createPinia } from "pinia";
import { createApp } from "vue";

import App from "./App.vue";
import { registerCodexServiceWorker } from "./service-worker";
import "./styles.css";

createApp(App).use(createPinia()).mount("#app");

if (import.meta.env.PROD && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    void registerCodexServiceWorker().catch(() => undefined);
  });
}
