import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// Explicitly include both participant entry and admin entry in the static build.
export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(process.cwd(), 'index.html'),
        admin: resolve(process.cwd(), 'admin.html'),
      },
    },
  },
});
