import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "AUTOLEAN_DASHBOARD_");
  const apiUrl = env.AUTOLEAN_DASHBOARD_API_URL ?? "http://127.0.0.1:8765";

  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: false,
      proxy: {
        "/api": apiUrl
      }
    }
  };
});
