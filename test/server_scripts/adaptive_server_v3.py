# -*- coding: utf-8 -*-
"""
🛡️ 靶机服务器 v3.0 (真实命令执行版)
新增功能：
1. 收到攻击时执行真实的系统命令
2. 生成真实的进程树供 PIDS 监控
3. 模拟真实的攻击场景
"""
import socket
import threading
import time
import subprocess
import os
from datetime import datetime

# ================= 配置区域 =================
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 7888
MAX_CONNECTIONS = 10
# ===========================================

# 颜色配置
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "reset": "\033[0m"
}

# 攻击特征
ATTACK_PATTERNS = {
    "SQL注入": ["union select", "or 1=1", "or '1'='1", "information_schema"],
    "目录遍历": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
    "远程命令执行": ["cmd=", "exec=", "system(", "whoami", "cat /etc"],
    "XSS攻击": ["<script>", "javascript:", "onerror="],
    "Webshell": ["eval(", "base64_decode", "<?php"],
}

# 统计
stats = {
    "total_requests": 0,
    "attacks_detected": 0,
    "commands_executed": 0,
    "start_time": None
}

def detect_attack(request_str):
    """检测攻击特征"""
    request_lower = request_str.lower()
    detected = []
    
    for attack_name, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in request_lower:
                detected.append(attack_name)
                break
    
    return list(set(detected))

def execute_attack_simulation(request_str):
    """
    根据攻击类型执行相应的系统命令（模拟真实攻击）
    这会生成真实的进程树供 PIDS 监控
    """
    request_lower = request_str.lower()
    commands_executed = []
    
    try:
        # 1. SQL 注入 - 模拟数据库查询
        if "union select" in request_lower or "sql" in request_lower:
            print(f"   {COLORS['yellow']}🔧 执行: SQL 查询模拟{COLORS['reset']}")
            subprocess.Popen(["sh", "-c", "echo 'SELECT * FROM users' > /dev/null"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            commands_executed.append("SQL查询")
        
        # 2. 目录遍历 - 读取文件
        if "../etc/passwd" in request_lower or "passwd" in request_lower:
            print(f"   {COLORS['yellow']}🔧 执行: 文件读取{COLORS['reset']}")
            subprocess.Popen(["cat", "/etc/hostname"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            commands_executed.append("cat")
        
        # 3. 远程命令执行 - 执行系统命令
        if "cmd=" in request_lower:
            # 提取命令参数
            if "whoami" in request_lower:
                print(f"   {COLORS['yellow']}🔧 执行: whoami{COLORS['reset']}")
                subprocess.Popen(["whoami"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                commands_executed.append("whoami")
            
            if "cat" in request_lower:
                print(f"   {COLORS['yellow']}🔧 执行: cat /etc/hostname{COLORS['reset']}")
                subprocess.Popen(["cat", "/etc/hostname"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                commands_executed.append("cat")
            
            if "ls" in request_lower:
                print(f"   {COLORS['yellow']}🔧 执行: ls{COLORS['reset']}")
                subprocess.Popen(["ls", "-la", "/tmp"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                commands_executed.append("ls")
        
        # 4. XSS 攻击 - 模拟脚本处理
        if "<script>" in request_lower:
            print(f"   {COLORS['yellow']}🔧 执行: 脚本处理{COLORS['reset']}")
            subprocess.Popen(["sh", "-c", "echo 'XSS detected' > /dev/null"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            commands_executed.append("脚本处理")
        
        # 5. Webshell - 执行复杂命令链
        if "<?php" in request_lower or "system(" in request_lower:
            print(f"   {COLORS['yellow']}🔧 执行: Webshell 命令链{COLORS['reset']}")
            # 模拟 Webshell 执行多个命令
            subprocess.Popen(["sh", "-c", "whoami && id && uname -a > /dev/null"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            commands_executed.append("Webshell链")
        
        if commands_executed:
            stats["commands_executed"] += len(commands_executed)
            print(f"   {COLORS['green']}✅ 已执行 {len(commands_executed)} 个命令: {', '.join(commands_executed)}{COLORS['reset']}")
            
            # 等待一下让进程启动
            time.sleep(0.2)
        
    except Exception as e:
        print(f"   {COLORS['red']}❌ 命令执行异常: {e}{COLORS['reset']}")

def handle_client(client_socket, client_addr):
    """处理客户端连接"""
    request_str = ""
    
    try:
        client_socket.settimeout(1)
        
        # 循环接收 HTTP 请求
        for attempt in range(5):
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_str += chunk.decode('utf-8', errors='ignore')
                if '\r\n\r\n' in request_str:
                    break
                if len(request_str) > 2048:
                    break
            except socket.timeout:
                if request_str:
                    continue
                else:
                    break
        
        # 更新统计
        stats["total_requests"] += 1
        
        # 解析请求行
        first_line = request_str.split('\r\n')[0] if '\r\n' in request_str else request_str[:100]
        
        # 打印请求日志
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{COLORS['blue']}📥 [{timestamp}] 收到请求 #{stats['total_requests']}{COLORS['reset']}")
        print(f"   来源: {client_addr[0]}:{client_addr[1]}")
        print(f"   请求: {first_line[:80]}{'...' if len(first_line) > 80 else ''}")
        
        if not request_str.strip():
            print(f"   {COLORS['yellow']}⚠️ 警告: 收到空请求{COLORS['reset']}")
        
        # 检测攻击特征
        attacks = detect_attack(request_str)
        if attacks:
            stats["attacks_detected"] += 1
            for attack in attacks:
                print(f"   {COLORS['red']}🔥 检测到: {attack}{COLORS['reset']}")
            
            # 🔥 执行攻击模拟（生成真实进程）
            execute_attack_simulation(request_str)
        
        # 发送 HTTP 响应
        response_body = "Hacked! Server pwned!"
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            "Connection: close\r\n"
            "Server: VulnerableServer/3.0\r\n"
            "\r\n"
            f"{response_body}"
        )
        
        client_socket.sendall(response.encode('utf-8'))
        print(f"   {COLORS['green']}✅ 响应已发送 (200 OK){COLORS['reset']}")
        
        time.sleep(0.05)
        
    except ConnectionResetError:
        print(f"   {COLORS['yellow']}⚠️ 客户端主动断开{COLORS['reset']}")
    except BrokenPipeError:
        pass
    except Exception as e:
        print(f"   {COLORS['red']}❌ 处理异常: {e}{COLORS['reset']}")
    finally:
        try:
            client_socket.shutdown(socket.SHUT_WR)
        except:
            pass
        client_socket.close()

def start_server():
    """启动服务器"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(MAX_CONNECTIONS)
        
        stats["start_time"] = datetime.now()
        
        print("="*60)
        print("🛡️ 靶机服务器 v3.0 (真实命令执行版)")
        print("="*60)
        print(f"📡 监听地址: {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"⏰ 启动时间: {stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        print("🚀 服务器已启动，等待连接...")
        print("   按 Ctrl+C 停止服务器")
        print("="*60 + "\n")
        
        while True:
            try:
                client_socket, client_addr = server_socket.accept()
                # 在新线程中处理客户端
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                client_thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{COLORS['red']}❌ 接受连接异常: {e}{COLORS['reset']}")
        
    except Exception as e:
        print(f"{COLORS['red']}❌ 服务器启动失败: {e}{COLORS['reset']}")
    finally:
        server_socket.close()
        
        # 打印统计信息
        if stats["start_time"]:
            runtime = datetime.now() - stats["start_time"]
            print("\n" + "="*60)
            print("📊 服务器统计:")
            print("="*60)
            print(f"   运行时间: {runtime}")
            print(f"   总请求数: {stats['total_requests']}")
            print(f"   攻击检测: {stats['attacks_detected']}")
            print(f"   命令执行: {stats['commands_executed']}")
            print("="*60)

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print(f"\n\n{COLORS['yellow']}👋 服务器已停止{COLORS['reset']}")
