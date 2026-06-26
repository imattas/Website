import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const isWebsitePagesBuild = process.env.GITHUB_REPOSITORY?.toLowerCase() === "imattas/website";

export default defineConfig({
  site: isWebsitePagesBuild ? "https://imattas.github.io" : "https://ianmattas.com/",
  base: isWebsitePagesBuild ? "/Website" : "/",
  vite: {
    plugins: [tailwindcss()]
  }
});
