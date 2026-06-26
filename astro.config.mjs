import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://ianmattas.com",
  base: "/",
  vite: {
    plugins: [tailwindcss()]
  }
});
