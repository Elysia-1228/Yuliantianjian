import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';

// 模拟 CommonJS 的 __filename 和 __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // 加载环境变量 (.env 文件)
  // process.cwd() 获取当前工作目录
  const env = loadEnv(mode, process.cwd(), '');

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
    define: {
      // 确保代码中使用的 API Key 在构建时被正确注入
      'process.env.API_KEY': JSON.stringify(env.API_KEY || ''),
    },
    server: {
      port: 3001,
      proxy: {
        // 开发环境代理配置：解决浏览器的同源策略 (CORS) 限制
        // 当前端请求 /api/xxx 时，Vite 会将其转发到 env.VITE_API_BASE_URL
        '/api': {
          target: env.VITE_API_BASE_URL || 'http://localhost:8985',
          changeOrigin: true,
          // rewrite: (path) => path.replace(/^\/api/, '') // 后端接口本身包含 /api 前缀，无需重写
        },
        // WebSocket 代理示例
        '/ids/stream': {
          target: env.VITE_IDS_WS_URL || 'ws://localhost:8985',
          ws: true,
          changeOrigin: true,
        }
      }
    }
  };
});