# 📦 御链天鉴 - 安装部署指南

> **适用版本**: v2.0  
> **更新日期**: 2025-01-26  
> **适用场景**: 开发环境 / 生产环境部署

---

## 📋 目录

- [环境要求](#环境要求)
- [快速安装](#快速安装)
- [详细安装步骤](#详细安装步骤)
- [配置说明](#配置说明)
- [启动服务](#启动服务)
- [验证安装](#验证安装)
- [常见问题](#常见问题)

---

## 🔧 环境要求

### 硬件要求

| 组件 | 最低配置 | 推荐配置 |
|------|---------|---------|
| **CPU** | 4核 | 8核+ |
| **内存** | 8GB | 16GB+ |
| **硬盘** | 50GB | 100GB+ SSD |
| **网络** | 100Mbps | 1Gbps |

### 软件要求

| 软件 | 版本要求 | 下载地址 | 说明 |
|------|---------|---------|------|
| **Java JDK** | 17+ | [Oracle JDK](https://www.oracle.com/java/technologies/downloads/) | 主后端运行环境 |
| **Maven** | 3.9+ | [Apache Maven](https://maven.apache.org/download.cgi) | Java 项目构建工具 |
| **Node.js** | 16+ | [Node.js](https://nodejs.org/) | 前端运行环境 |
| **Python** | 3.8+ | [Python](https://www.python.org/downloads/) | IDS 检测引擎 |
| **MySQL** | 8.0+ | [MySQL](https://dev.mysql.com/downloads/mysql/) | 主数据库 |
| **Redis** | 6.0+ | [Redis](https://redis.io/download) | 缓存数据库 |

### 操作系统支持

- ✅ Windows 10/11
- ✅ Windows Server 2016+
- ✅ Ubuntu 20.04+
- ✅ CentOS 7+
- ✅ macOS 11+

---

## ⚡ 快速安装

### 方式一：一键安装脚本（Windows）

```bash
# 1. 克隆项目
git clone https://github.com/Elysia-1228/Yuliantianjian.git
cd Yuliantianjian

# 2. 导入数据库
mysql -u root -p < net_safe-v2.sql

# 3. 修改配置文件（见下方配置说明）

# 4. 一键启动
scripts\start-all.bat
```

### 方式二：Docker 部署（推荐生产环境）

```bash
# 即将推出...
docker-compose up -d
```

---

## 📝 详细安装步骤

### 步骤 1：安装 Java 环境

#### Windows

1. 下载 JDK 17：https://www.oracle.com/java/technologies/downloads/#java17
2. 运行安装程序，默认安装路径：`C:\Program Files\Java\jdk-17`
3. 配置环境变量：
   ```
   JAVA_HOME = C:\Program Files\Java\jdk-17
   Path 添加 = %JAVA_HOME%\bin
   ```
4. 验证安装：
   ```bash
   java -version
   # 应显示：java version "17.x.x"
   ```

#### Linux

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-17-jdk

# CentOS/RHEL
sudo yum install java-17-openjdk-devel

# 验证
java -version
```

---

### 步骤 2：安装 Maven

#### Windows

1. 下载 Maven：https://maven.apache.org/download.cgi
2. 解压到：`C:\apache-maven-3.9.6`
3. 配置环境变量：
   ```
   MAVEN_HOME = C:\apache-maven-3.9.6
   Path 添加 = %MAVEN_HOME%\bin
   ```
4. 验证安装：
   ```bash
   mvn -version
   ```

#### Linux

```bash
# Ubuntu/Debian
sudo apt install maven

# CentOS/RHEL
sudo yum install maven

# 验证
mvn -version
```

---

### 步骤 3：安装 Node.js

#### Windows

1. 下载 Node.js：https://nodejs.org/
2. 运行安装程序（推荐 LTS 版本）
3. 验证安装：
   ```bash
   node -v
   npm -v
   ```

#### Linux

```bash
# 使用 NodeSource 仓库
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 验证
node -v
npm -v
```

---

### 步骤 4：安装 MySQL

#### Windows

1. 下载 MySQL Installer：https://dev.mysql.com/downloads/installer/
2. 选择 "Developer Default" 安装类型
3. 设置 root 密码（请记住此密码）
4. 完成安装后，启动 MySQL 服务

#### Linux

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation

# CentOS/RHEL
sudo yum install mysql-server
sudo systemctl start mysqld
sudo mysql_secure_installation
```

---

### 步骤 5：安装 Redis

#### Windows

1. 下载 Redis for Windows：https://github.com/tporadowski/redis/releases
2. 解压并运行 `redis-server.exe`
3. 或安装为 Windows 服务：
   ```bash
   redis-server --service-install
   redis-server --service-start
   ```

#### Linux

```bash
# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# CentOS/RHEL
sudo yum install redis
sudo systemctl start redis
sudo systemctl enable redis

# 验证
redis-cli ping
# 应返回：PONG
```

---

### 步骤 6：安装 Python 环境

#### Windows

1. 下载 Python：https://www.python.org/downloads/
2. 安装时勾选 "Add Python to PATH"
3. 验证安装：
   ```bash
   python --version
   pip --version
   ```

#### Linux

```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip

# 验证
python3 --version
pip3 --version
```

---

### 步骤 7：克隆项目

```bash
# 使用 HTTPS
git clone https://github.com/Elysia-1228/Yuliantianjian.git

# 或使用 SSH
git clone git@github.com:Elysia-1228/Yuliantianjian.git

# 进入项目目录
cd Yuliantianjian
```

---

### 步骤 8：初始化数据库

```bash
# 1. 登录 MySQL
mysql -u root -p

# 2. 创建数据库（如果脚本中未包含）
CREATE DATABASE IF NOT EXISTS net_safe CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 3. 退出 MySQL
exit

# 4. 导入数据库脚本
mysql -u root -p net_safe < net_safe-v2.sql

# 5. 验证导入
mysql -u root -p -e "USE net_safe; SHOW TABLES;"
# 应显示 15 张表
```

---

## ⚙️ 配置说明

### 1. 主后端配置（BackCode）

编辑文件：`BackCode/src/main/resources/application-dev.yml`

```yaml
safe:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    host: localhost          # MySQL 主机地址
    port: 3306              # MySQL 端口
    database: net_safe      # 数据库名称
    username: root          # 数据库用户名
    password: your_password # 数据库密码（请修改）
redis:
    host: localhost         # Redis 主机地址
    port: 6379             # Redis 端口
    password: root         # Redis 密码（请修改）
    database: 10           # Redis 数据库编号

# AI 引擎配置（可选）
ai:
  engine:
    url: http://10.138.50.151:5000/predict  # AI 引擎地址
    timeout: 30000                           # 超时时间（毫秒）
```

### 2. 区块链后端配置（backend）

编辑文件：`backend/src/main/resources/application.yml`

```yaml
server:
  port: 8080

spring:
  application:
    name: blockchain-backend

# Hyperledger Fabric 配置
fabric:
  network:
    name: net_safe_network
    channel: mychannel
    chaincode: evidence
  connection:
    profile: connection-org1.yaml
  wallet:
    path: wallet
```

### 3. 前端配置（FrontCode）

编辑文件：`FrontCode/src/api/config.js`（如果存在）

```javascript
// API 基础地址
export const API_BASE_URL = 'http://localhost:8985/api';
export const BLOCKCHAIN_API_URL = 'http://localhost:8080/api';
export const WS_URL = 'ws://localhost:8985/ws';
```

### 4. Python IDS 配置

编辑文件：`PythonIDS/alert_gateway/config.py`（如果存在）

```python
# 后端 API 地址
BACKEND_API_URL = 'http://localhost:8985/api'

# Flask 服务端口
FLASK_PORT = 5000
```

---

## 🚀 启动服务

### 方式一：一键启动（Windows）

```bash
# 使用批处理脚本
scripts\start-all.bat

# 或使用 PowerShell 脚本
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
```

### 方式二：手动启动

#### 1. 启动主后端（BackCode）

```bash
cd BackCode
mvn clean install
mvn spring-boot:run

# 或使用已编译的 JAR
java -jar target/backcode-1.0.0.jar

# 启动成功标志：
# Started BackCodeApplication in X.XXX seconds
# 访问：http://localhost:8985
```

#### 2. 启动区块链后端（backend）

```bash
cd backend
mvn clean install
mvn spring-boot:run

# 或使用已编译的 JAR
java -jar target/blockchain-backend-1.0.0.jar

# 启动成功标志：
# Started BlockchainApplication in X.XXX seconds
# 访问：http://localhost:8080
```

#### 3. 启动前端（FrontCode）

```bash
cd FrontCode

# 首次运行需要安装依赖
npm install

# 启动开发服务器
npm run dev

# 启动成功标志：
# VITE v4.x.x ready in XXX ms
# ➜ Local: http://localhost:3000/
```

#### 4. 启动 Python IDS（可选）

```bash
cd PythonIDS

# 安装依赖
pip install -r requirements.txt

# 启动告警网关
cd alert_gateway
python app.py

# 启动成功标志：
# * Running on http://0.0.0.0:5000
```

---

## ✅ 验证安装

### 1. 检查服务状态

```bash
# 检查主后端
curl http://localhost:8985/api/health
# 应返回：{"status":"UP"}

# 检查区块链后端
curl http://localhost:8080/api/health
# 应返回：{"status":"UP"}

# 检查前端
# 浏览器访问：http://localhost:3000
# 应显示登录页面
```

### 2. 测试登录

1. 访问：http://localhost:3000
2. 使用默认账号登录：
   - 用户名：`admin`
   - 密码：`admin123`（请查看数据库中的实际密码）
3. 登录成功后应显示主控制台

### 3. 检查数据库连接

```bash
# 登录 MySQL
mysql -u root -p

# 查看数据
USE net_safe;
SELECT COUNT(*) FROM userinfo;
# 应显示用户数量
```

### 4. 检查 Redis 连接

```bash
# 连接 Redis
redis-cli

# 测试
PING
# 应返回：PONG

# 查看键
KEYS *
```

---

## ❓ 常见问题

### Q1: 主后端启动失败，提示数据库连接错误

**解决方案**：
1. 检查 MySQL 是否启动：
   ```bash
   # Windows
   net start MySQL80
   
   # Linux
   sudo systemctl status mysql
   ```
2. 验证数据库配置：
   - 用户名、密码是否正确
   - 数据库名称是否存在
   - 端口是否正确（默认 3306）
3. 测试连接：
   ```bash
   mysql -h localhost -u root -p
   ```

### Q2: 前端无法连接后端，提示 CORS 错误

**解决方案**：
1. 确认后端已启动并监听 8985 端口
2. 检查后端 CORS 配置（应已配置允许跨域）
3. 清除浏览器缓存并重新加载

### Q3: Maven 下载依赖很慢

**解决方案**：
配置国内镜像源，编辑 `~/.m2/settings.xml`：

```xml
<mirrors>
  <mirror>
    <id>aliyun</id>
    <mirrorOf>central</mirrorOf>
    <name>Aliyun Maven</name>
    <url>https://maven.aliyun.com/repository/public</url>
  </mirror>
</mirrors>
```

### Q4: npm install 失败或很慢

**解决方案**：
使用国内镜像源：

```bash
# 使用淘宝镜像
npm config set registry https://registry.npmmirror.com

# 或使用 cnpm
npm install -g cnpm --registry=https://registry.npmmirror.com
cnpm install
```

### Q5: Redis 连接失败

**解决方案**：
1. 检查 Redis 是否启动：
   ```bash
   # Windows
   redis-cli ping
   
   # Linux
   sudo systemctl status redis
   ```
2. 检查 Redis 配置文件中的绑定地址和端口
3. 如果设置了密码，确保配置文件中的密码正确

### Q6: 端口被占用

**解决方案**：
```bash
# Windows 查看端口占用
netstat -ano | findstr :8985
taskkill /PID <进程ID> /F

# Linux 查看端口占用
lsof -i :8985
kill -9 <进程ID>

# 或修改配置文件中的端口号
```

### Q7: Python IDS 启动失败

**解决方案**：
1. 确认 Python 版本 >= 3.8
2. 安装所有依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 如果缺少某些系统库，根据错误提示安装

### Q8: 区块链后端无法连接 Fabric 网络

**解决方案**：
1. 确认 Hyperledger Fabric 网络已启动
2. 检查连接配置文件路径是否正确
3. 验证证书和密钥文件是否存在
4. 查看日志文件获取详细错误信息

---

## 📞 获取帮助

如果遇到其他问题，请：

1. 查看项目文档：`docs/` 目录
2. 查看日志文件：
   - 主后端：`BackCode/logs/`
   - 区块链后端：`backend/logs/`
   - Python IDS：`PythonIDS/logs/`
3. 提交 Issue：https://github.com/Elysia-1228/Yuliantianjian/issues

---

## 🔄 下一步

安装完成后，请参考：
- [QUICKSTART.md](QUICKSTART.md) - 快速开始指南
- [docs/启动指南.md](docs/启动指南.md) - 详细使用说明
- [README.md](README.md) - 项目概述

---

**© 2025 Yuliantianjian - 御链天鉴网络安全平台**
