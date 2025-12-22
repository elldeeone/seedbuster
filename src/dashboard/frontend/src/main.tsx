import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";

// Dev-only mode helper: when running Vite directly, inject a mode flag for admin/public.
if (import.meta.env.DEV && typeof window !== "undefined" && !(window as any).__SB_MODE) {
  const envMode = (import.meta.env.VITE_SPA_MODE as string | undefined)?.toLowerCase();
  const pathMode = window.location.pathname.startsWith("/admin") ? "admin" : "public";
  (window as any).__SB_MODE = envMode === "admin" ? "admin" : pathMode;
}

createRoot(document.getElementById("root")!).render(<App />);
