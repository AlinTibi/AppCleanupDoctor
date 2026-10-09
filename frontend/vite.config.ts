import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [{
    name: 'local-development-styles',
    apply: 'serve',
    // Vite's local HMR injects styles. Production keeps the strict static CSP.
    transformIndexHtml(html) {
      return html.replace("style-src 'self';", "style-src 'self' 'unsafe-inline';");
    },
  }],
});
