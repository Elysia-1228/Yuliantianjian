/// <reference types="vite/client" />

interface ImportMetaEnv {
  // 定义 .env 文件中存在的变量，以便获得代码提示
  readonly VITE_API_BASE_URL: string
  readonly VITE_IDS_WS_URL: string
  readonly VITE_BLOCKCHAIN_NODE: string
  readonly API_KEY: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}