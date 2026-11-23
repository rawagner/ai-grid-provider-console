import { federation } from '@module-federation/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const port = Number(process.env.FRONTEND_PORT ?? 9000);

export default defineConfig(({ command }) => {
  return {
    base: command === 'serve' ? '/' : '/plugins/ai-grid-provider-console/',
    publicDir: 'plugin-manifest',
    server: {
      port,
      strictPort: true,
      cors: true,
      origin: `http://localhost:${port}`,
    },
    optimizeDeps: {
      // Federation adds these imports after Vite's initial dependency scan.
      include: ['@module-federation/runtime', '@module-federation/runtime/helpers'],
    },
    plugins: [
      react(),
      federation({
        name: 'ai-grid-provider-console',
        manifest: true,
        dts: false,
        exposes: {
          './AIGridContextProvider': './src/plugin/AIGridContextProvider.tsx',
          './OrganizationsPage': './src/plugin/OrganizationsPage.tsx',
        },
        shared: {
          react: { singleton: true },
          'react/': { singleton: true },
          'react-dom': { singleton: true },
          'react-dom/': { singleton: true },
          'react-router': { singleton: true },
          'react-router-dom': { singleton: true },
        },
      }),
    ],
    build: {
      outDir: 'dist',
      emptyOutDir: true,
    },
  };
});
