# 🚀 御链天鉴 - 快速开始指南

> **阅读时间**: 5 分钟  
> **适用人群**: 从 GitHub 下载本项目的开发者和使用者  
> **前置条件**: 已完成 [INSTALLATION.md](INSTALLATION.md) 中的环境安装

---

## 📖 项目简介

**御链天鉴（Yuliantianjian）** 是一个企业级网络安全态势感知与主动防御平台，主要功能包括：

- 🔍 **入侵检测**：基于 Snort 规则引擎 + TransEC-GAN 深度学习模型
- 🔗 **区块链存证**：基于 Hyperledger Fabric 的不可篡改安全日志
- 🤖 **AI 威胁分析**：自动生成 PIDS 溯源图谱
- 🚨 **主动防御**：自动封禁恶意 IP，支持白名单管理
- 📊 **态势感知**：实时可视化网络安全态势

---

## ⚡ 5 分钟快速启动

### 步骤 1：克隆项目

```bash
git clone https://github.com/Elysia-1228/Yuliantianjian.git
cd Yuliantianjian
```

### 步骤 2：初始化数据库

```bash
# 登录 MySQL
mysql -u root -p

# 导入数据库
mysql -u root -p < net_safe-v2.sql
```

### 步骤 3：修改配置

编辑 `BackCode/src/main/resources/application-dev.yml`：

```yaml
safe:
  datasource:
    username: root
    password: 你的MySQL密码  # 修改这里
redis:
    password: 你的Redis密码  # 修改这里（如果设置了密码）
```

### 步骤 4：一键启动

**Windows 用户**：
```bash
scripts\start-all.bat
```

**Linux/Mac 用户**：
```bash
# 需要手动启动各个服务（见下方详细说明）
```

### 步骤 5：访问系统

打开浏览器访问：**http://localhost:3000**

默认登录账号：
- 用户名：`admin`
- 密码：查看数据库 `userinfo` 表中的密码

---

## 🎯 核心功能使用指南

### 1. 威胁检测与分析

#### 查看实时告警
1. 登录系统后，点击左侧菜单 **"威胁检测"** → **"实时告警"**
2. 查看最新的安全威胁事件列表
3. 点击任意告警可查看详细信息

#### 生成 PIDS 溯源图谱
1. 进入 **"威胁分析"** → **"PIDS 图谱"**
2. 选择要分析的威胁事件
3. 点击 **"生成图谱"** 按钮
4. 系统将调用 AI 引擎自动生成攻击路径可视化图谱
5. 支持节点拖拽、缩放、高亮等交互操作

**特性**：
- ✅ 自动轮询更新（每 2 秒）
- ✅ 增量合并新节点
- ✅ 按源 IP 筛选告警
- ✅ AI 引擎离线自动降级

### 2. 主动防御

#### 封禁恶意 IP
1. 进入 **"主动防御"** → **"IP 管理"**
2. 点击 **"添加黑名单"**
3. 输入要封禁的 IP 地址
4. 选择封禁时长（临时/永久）
5. 点击 **"确认"** 完成封禁

#### 白名单管理
1. 进入 **"主动防御"** → **"白名单管理"**
2. 添加受信任的 IP 地址
3. 白名单中的 IP 不会被自动封禁

### 3. 区块链存证

#### 上传安全事件到链
1. 进入 **"区块链存证"** → **"事件上链"**
2. 选择要存证的安全事件
3. 点击 **"批量上链"** 或 **"单个上链"**
4. 系统将事件数据加密后上传到 Hyperledger Fabric 区块链

#### 查询链上数据
1. 进入 **"区块链存证"** → **"链上查询"**
2. 输入查询条件（威胁 ID、源 IP、时间范围等）
3. 点击 **"查询"** 查看链上存证记录
4. 支持导出查询结果

**特性**：
- ✅ 不可篡改的安全日志
- ✅ 支持富查询（复杂条件检索）
- ✅ 异步批处理（高性能）
- ✅ 敏感字段 AES 加密

### 4. 态势感知

#### 实时态势大屏
1. 进入 **"态势感知"** → **"全景视图"**
2. 查看实时网络安全态势：
   - 威胁等级分布
   - 攻击类型统计
   - 流量趋势图
   - 地理位置分布

#### 3D 网络拓扑
1. 进入 **"态势感知"** → **"银河拓扑图"**
2. 3D 可视化展示网络拓扑结构
3. 支持节点交互、缩放、旋转

---

## 📂 项目结构说明

```
Yuliantianjian/
├── BackCode/           # 主后端服务（端口 8985）
│   ├── src/           # 源代码
│   └── pom.xml        # Maven 依赖配置
│
├── backend/           # 区块链后端（端口 8080）
│   ├── src/           # 源代码
│   └── pom.xml        # Maven 依赖配置
│
├── FrontCode/         # 前端项目（端口 3000）
│   ├── src/           # React 源代码
│   ├── package.json   # NPM 依赖配置
│   └── vite.config.js # Vite 构建配置
│
├── PythonIDS/         # Python 入侵检测系统（端口 5000）
│   ├── anomaly_based_ids/  # 异常检测模块
│   ├── rule_based_ids/     # 规则检测模块
│   └── alert_gateway/      # 告警网关
│
├── docs/              # 项目文档
├── scripts/           # 启动脚本
├── net_safe-v2.sql    # 数据库初始化脚本
├── README.md          # 项目说明
├── INSTALLATION.md    # 安装指南
└── QUICKSTART.md      # 快速开始（本文件）
```

---

## 🔧 手动启动服务（详细步骤）

如果一键启动脚本不可用，可以手动启动各个服务：

### 1. 启动 MySQL 和 Redis

```bash
# Windows
net start MySQL80
net start Redis

# Linux
sudo systemctl start mysql
sudo systemctl start redis
```

### 2. 启动主后端（BackCode）

```bash
cd BackCode
mvn clean package -DskipTests
java -jar target/backcode-1.0.0.jar

# 或使用 Maven 直接运行
mvn spring-boot:run
```

**启动成功标志**：
```
Started BackCodeApplication in X.XXX seconds
Application is running on port 8985
```

### 3. 启动区块链后端（backend）

```bash
cd backend
mvn clean package -DskipTests
java -jar target/blockchain-backend-1.0.0.jar

# 或使用 Maven 直接运行
mvn spring-boot:run
```

**启动成功标志**：
```
Started BlockchainApplication in X.XXX seconds
Application is running on port 8080
```

### 4. 启动前端（FrontCode）

```bash
cd FrontCode

# 首次运行需要安装依赖
npm install

# 启动开发服务器
npm run dev
```

**启动成功标志**：
```
VITE v4.x.x ready in XXX ms
➜ Local: http://localhost:3000/
```

### 5. 启动 Python IDS（可选）

```bash
cd PythonIDS

# 安装依赖
pip install -r requirements.txt

# 启动告警网关
cd alert_gateway
python app.py
```

**启动成功标志**：
```
* Running on http://0.0.0.0:5000
* Debugger is active!
```

---

## ✅ 验证系统运行

### 检查服务状态

```bash
# 1. 检查主后端
curl http://localhost:8985/api/health
# 预期返回：{"status":"UP"}

# 2. 检查区块链后端
curl http://localhost:8080/api/health
# 预期返回：{"status":"UP"}

# 3. 检查前端
# 浏览器访问：http://localhost:3000
# 应显示登录页面

# 4. 检查 Python IDS（如果启动）
curl http://localhost:5000/health
# 预期返回：{"status":"running"}
```

### 测试登录

1. 访问：http://localhost:3000
2. 输入用户名和密码
3. 登录成功后应显示主控制台

---

## 🎓 学习路径

### 新手入门
1. ✅ 完成快速启动（本文档）
2. 📖 阅读 [README.md](README.md) 了解项目架构
3. 🔍 浏览各个功能模块，熟悉界面
4. 📊 查看示例数据和图表

### 进阶使用
1. 📚 阅读 [docs/项目代码结构文档.md](docs/项目代码结构文档.md)
2. 🔧 了解配置文件的详细参数
3. 🧪 测试 API 接口（参考 `test/API全面测试报告.md`）
4. 🎨 自定义前端界面和功能

### 开发者指南
1. 💻 搭建开发环境（IDE、调试工具）
2. 🔍 阅读源代码，理解业务逻辑
3. 🧩 学习各个模块的交互方式
4. 🚀 参与贡献（提交 PR、报告 Bug）

---

## 📋 常用命令速查

### Maven 命令
```bash
# 清理编译
mvn clean

# 编译项目
mvn compile

# 打包（跳过测试）
mvn package -DskipTests

# 运行 Spring Boot 应用
mvn spring-boot:run

# 安装到本地仓库
mvn install
```

### NPM 命令
```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览生产构建
npm run preview

# 清除缓存
npm cache clean --force
```

### Git 命令
```bash
# 拉取最新代码
git pull origin main

# 查看状态
git status

# 创建新分支
git checkout -b feature/your-feature

# 提交更改
git add .
git commit -m "描述你的更改"
git push origin feature/your-feature
```

---

## ❓ 常见问题

### Q1: 启动后无法访问前端页面

**解决方案**：
1. 检查前端是否成功启动（查看终端输出）
2. 确认端口 3000 没有被占用
3. 清除浏览器缓存并刷新
4. 检查防火墙设置

### Q2: 登录失败，提示用户名或密码错误

**解决方案**：
1. 检查数据库是否正确导入
2. 查询数据库获取正确的用户名和密码：
   ```sql
   SELECT username, password FROM userinfo;
   ```
3. 如果密码是加密的，可能需要重置密码

### Q3: PIDS 图谱无法生成

**解决方案**：
1. 检查 AI 引擎服务是否启动（`http://10.138.50.151:5000`）
2. 如果 AI 引擎不可用，系统会自动降级使用本地算法
3. 查看后端日志获取详细错误信息

### Q4: 区块链上链失败

**解决方案**：
1. 确认 Hyperledger Fabric 网络已启动
2. 检查区块链后端日志
3. 验证证书和配置文件是否正确
4. 如果是开发环境，可以暂时跳过区块链功能

### Q5: 端口冲突

**解决方案**：
```bash
# 查看端口占用（Windows）
netstat -ano | findstr :8985

# 查看端口占用（Linux）
lsof -i :8985

# 修改配置文件中的端口号
# BackCode: application.yml 中的 server.port
# FrontCode: vite.config.js 中的 server.port
```

---

## 📞 获取帮助

如果遇到问题，可以通过以下方式获取帮助：

1. **查看文档**：
   - [README.md](README.md) - 项目概述
   - [INSTALLATION.md](INSTALLATION.md) - 详细安装指南
   - [docs/](docs/) - 更多文档

2. **查看日志**：
   - 主后端：`BackCode/logs/`
   - 区块链后端：`backend/logs/`
   - Python IDS：`PythonIDS/logs/`

3. **提交 Issue**：
   - GitHub Issues: https://github.com/Elysia-1228/Yuliantianjian/issues

4. **联系维护者**：
   - 项目维护者：Zhilian Security Team

---

## 🔄 下一步

完成快速启动后，建议：

1. 📖 深入阅读 [README.md](README.md) 了解完整功能
2. 🔧 参考 [INSTALLATION.md](INSTALLATION.md) 进行生产环境部署
3. 📚 浏览 [docs/](docs/) 目录下的详细文档
4. 🧪 运行测试用例，熟悉 API 接口
5. 🎨 根据需求自定义配置和功能

---

## 🎉 开始使用

现在你已经成功启动了御链天鉴平台！

开始探索各项功能，保护你的网络安全吧！🛡️

---

**© 2025 Yuliantianjian - 御链天鉴网络安全平台**

[⬆ 回到顶部](#-御链天鉴---快速开始指南)
