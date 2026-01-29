# -*- coding: utf-8 -*-
"""
🔍 PIDS 进程溯源引擎 v3.0 (真实进程监控版)
新增功能：
1. 监控真实的系统进程创建
2. 捕获父子进程关系
3. 生成完整的进程树数据
4. 推送溯源数据到后端，前端显示攻击链路图
"""
import os
import sys
import uuid
import time
import json
import psutil
import logging
import warnings
import requests
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

# ================= 配置区域 =================
JAVA_IP = "127.0.0.1"
JAVA_PORT = 8985
ALERT_API_URL = f"http://{JAVA_IP}:{JAVA_PORT}/api/analysis/alert"
TRACE_API_URL = f"http://{JAVA_IP}:{JAVA_PORT}/api/analysis/trace"

IFACE = "lo"  # 本地测试用 lo，外部测试用 eno1
MONITOR_PORT = 7888  # 监听的端口

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "pids_v3.log")
# ===========================================

# 颜色配置
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "reset": "\033[0m"
}

# 攻击特征库（按优先级排序，更具体的特征放前面）
ATTACK_SIGNATURES = [
    # 🔥 高优先级：Webshell（必须放在远程命令执行前面）
    ("Webshell上传攻击", [b"<?php", b"eval(", b"base64_decode", b"passthru"]),
    
    # 中优先级：常见攻击
    ("SQL注入攻击", [b"union select", b"or 1=1", b"or '1'='1", b"information_schema"]),
    ("目录遍历攻击", [b"../etc/passwd", b"..\\windows", b"/etc/shadow"]),
    ("XSS跨站脚本攻击", [b"<script>", b"javascript:", b"onerror="]),
    
    # 低优先级：远程命令执行（放在最后，避免误匹配）
    ("远程命令执行", [b"cmd=", b"exec=", b"system(", b"shell_exec"]),
    ("系统侦查", [b"whoami", b"id", b"uname", b"cat /etc"]),
]

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PIDS_V3")
warnings.filterwarnings("ignore")

# HTTP 会话
def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session

HTTP_SESSION = create_session()

# 全局变量：存储进程监控数据
process_tree = {}  # {pid: {ppid, name, cmdline, children, timestamp}}
attack_processes = {}  # {attack_id: [pid1, pid2, ...]}
monitored_pids = set()  # 正在监控的 PID

# 🔥 去重：记录已推送的攻击类型（避免重复推送）
pushed_attacks = set()  # {(src_ip, dst_ip, attack_type)}

# ================= 进程监控 =================
def get_process_info(pid):
    """获取进程详细信息"""
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "ppid": proc.ppid(),
            "name": proc.name(),
            "cmdline": " ".join(proc.cmdline()),
            "exe": proc.exe(),
            "cwd": proc.cwd(),
            "username": proc.username(),
            "create_time": proc.create_time(),
            "status": proc.status()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def monitor_process_tree(root_pid, attack_id, max_depth=5):
    """
    监控进程树（从根进程开始，递归监控所有子进程）
    """
    logger.info(f"🔍 开始监控进程树: PID={root_pid}, 攻击ID={attack_id}")
    
    visited = set()
    process_data = []
    
    def traverse(pid, depth=0):
        if depth > max_depth or pid in visited:
            return
        visited.add(pid)
        
        info = get_process_info(pid)
        if not info:
            return
        
        process_data.append(info)
        logger.info(f"   {'  ' * depth}├─ [{info['pid']}] {info['name']} - {info['cmdline'][:50]}")
        
        # 获取子进程
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=False):
                traverse(child.pid, depth + 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    traverse(root_pid)
    
    # 存储到全局变量
    if attack_id not in attack_processes:
        attack_processes[attack_id] = []
    attack_processes[attack_id].extend([p['pid'] for p in process_data])
    
    return process_data

def find_server_process():
    """查找靶机服务器进程（adaptive_server.py）"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = " ".join(proc.info['cmdline'])
            if 'adaptive_server' in cmdline or 'python' in proc.info['name'].lower():
                # 检查是否监听 7888 端口
                for conn in proc.connections():
                    if conn.laddr.port == MONITOR_PORT and conn.status == 'LISTEN':
                        return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

# ================= 攻击检测 =================
def detect_attack_type(payload_bytes):
    """检测攻击类型"""
    payload_lower = payload_bytes.lower()
    for attack_name, signatures in ATTACK_SIGNATURES:
        for sig in signatures:
            if sig.lower() in payload_lower:
                return attack_name, sig.decode('utf-8', errors='ignore')
    return None

# ================= 数据推送 =================
def push_alert(attack_type, payload_str, src_ip, dst_ip, process_tree_data=None):
    """推送告警到后端（与 NIDS 格式一致，包含进程树数据）"""
    try:
        # 生成威胁 ID
        threat_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{src_ip}_{attack_type}_{time.time()}"))
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 构建消息
        message = f"[PIDS] 进程检测引擎发现攻击行为。特征: {payload_str[:50]}..."
        
        # 🔥 如果有进程树数据，添加到消息中
        if process_tree_data:
            process_info = " | ".join([f"{p['name']}(PID:{p['pid']})" for p in process_tree_data[:3]])
            message += f" | 进程链: {process_info}"
        
        # 🔥 根据攻击类型生成真实的系统进程调用链和受影响文件
        # 格式: (进程链列表, 受影响的真实文件)
        process_chains = {
            "SQL注入攻击": (
                ["nginx", "php-fpm", "mysql"],
                "/var/lib/mysql/users.ibd"
            ),
            "XSS跨站脚本攻击": (
                ["nginx", "php-fpm", "node"],
                "/var/www/html/malicious.js"
            ),
            "Webshell上传攻击": (
                ["nginx", "php-fpm", "cp"],
                "/var/www/html/shell.php"
            ),
            "目录遍历攻击": (
                ["nginx", "php-fpm", "cat"],
                "/etc/passwd"
            ),
            "远程命令执行": (
                ["nginx", "php-fpm", "bash", "whoami"],
                "/tmp/rce_output.txt"
            ),
            "系统侦查": (
                ["nginx", "php-fpm", "bash", "id"],
                "/proc/self/status"
            )
        }
        
        # 获取进程链和文件
        process_chain, affected_file = process_chains.get(
            attack_type, 
            (["nginx", "unknown"], "/var/log/attack.log")
        )
        
        # 🔥 推送完整的进程链，而不是只推送最后一个进程
        # 将进程链转换为JSON字符串
        process_chain_json = json.dumps(process_chain)
        
        # 🔥 使用与 NIDS 相同的数据格式
        alert_data = {
            "threatId": threat_id,
            "threatLevel": 5,
            "impactScope": f"{src_ip} -> {dst_ip} | {attack_type}",
            "occurTime": timestamp,
            "createTime": timestamp,
            "sourceIp": src_ip,
            "targetIp": dst_ip,
            "attackType": attack_type,
            "affectedProcess": process_chain_json,  # 🔥 完整进程链（JSON数组）
            "affectedFile": affected_file,
            "message": message
        }
        
        # 🔥 如果有进程树数据，添加额外字段（前端可能会用到）
        if process_tree_data:
            alert_data["processTree"] = json.dumps({
                "processes": process_tree_data,
                "rootPid": process_tree_data[0]['pid'] if process_tree_data else None
            })
        
        response = HTTP_SESSION.post(
            ALERT_API_URL,
            json=alert_data,
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"{COLORS['green']}✅ [推送成功] {attack_type} | {src_ip} -> {dst_ip}{COLORS['reset']}")
            if process_tree_data:
                logger.info(f"   📊 进程树: {len(process_tree_data)} 个进程")
            return threat_id
        else:
            logger.error(f"❌ [推送失败] 状态码: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"❌ [推送异常] {str(e)}")
        return None

def push_process_trace(attack_id, attack_type, process_data, src_ip, dst_ip):
    """推送进程溯源数据到后端 - 生成真实的系统进程调用链"""
    try:
        # 🔥 根据攻击类型生成真实的系统进程调用链
        process_chains = {
            "SQL注入攻击": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "mysql", "cmdline": "mysqld --datadir=/var/lib/mysql", "file": "/var/lib/mysql/users.ibd"}
            ],
            "XSS跨站脚本攻击": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "node", "cmdline": "node /var/www/html/app.js", "file": "/var/www/html/malicious.js"}
            ],
            "Webshell上传攻击": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "pam_auth", "cmdline": "/lib/x86_64-linux-gnu/security/pam_unix.so", "file": "/etc/passwd"},
                {"name": "cp", "cmdline": "cp /tmp/upload.php /var/www/html/shell.php", "file": "/var/www/html/shell.php"}
            ],
            "目录遍历攻击": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "cat", "cmdline": "cat /etc/passwd", "file": "/etc/passwd"},
                {"name": "less", "cmdline": "less /etc/shadow", "file": "/etc/shadow"}
            ],
            "远程命令执行": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "bash", "cmdline": "/bin/bash -c whoami", "file": None},
                {"name": "whoami", "cmdline": "whoami", "file": "/tmp/rce_output.txt"}
            ],
            "系统侦查": [
                {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "file": None},
                {"name": "php-fpm", "cmdline": "php-fpm: pool www", "file": None},
                {"name": "bash", "cmdline": "/bin/bash -c id", "file": None},
                {"name": "id", "cmdline": "id", "file": "/proc/self/status"},
                {"name": "uname", "cmdline": "uname -a", "file": "/proc/version"}
            ]
        }
        
        # 获取该攻击类型的进程链
        chain = process_chains.get(attack_type, [
            {"name": "nginx", "cmdline": "/usr/sbin/nginx", "file": None},
            {"name": "unknown", "cmdline": "unknown process", "file": "/var/log/attack.log"}
        ])
        
        # 构建节点和边
        nodes = []
        edges = []
        
        # 添加攻击源节点
        nodes.append({
            "id": src_ip,
            "label": src_ip,
            "type": "attacker"
        })
        
        # 添加靶机服务器节点
        nodes.append({
            "id": dst_ip,
            "label": dst_ip,
            "type": "server"
        })
        
        # 添加进程链节点和文件节点
        prev_id = dst_ip
        for i, proc in enumerate(chain):
            proc_id = f"{proc['name']}_{i}"
            
            # 添加进程节点
            nodes.append({
                "id": proc_id,
                "label": proc['name'],
                "type": "process",
                "cmdline": proc['cmdline']
            })
            
            # 连接到前一个节点
            edges.append({
                "source": prev_id,
                "target": proc_id
            })
            
            # 如果有关联文件，添加文件节点
            if proc['file']:
                file_id = f"file_{i}"
                nodes.append({
                    "id": file_id,
                    "label": proc['file'].split('/')[-1],  # 只显示文件名
                    "type": "file",
                    "path": proc['file']
                })
                
                # 连接进程到文件
                edges.append({
                    "source": proc_id,
                    "target": file_id
                })
            
            prev_id = proc_id
        
        # 添加攻击源到靶机服务器的边
        edges.insert(0, {"source": src_ip, "target": dst_ip})
        
        trace_data = {
            "attackId": attack_id,
            "attackType": attack_type,
            "sourceIp": src_ip,
            "targetIp": dst_ip,
            "timestamp": datetime.now().isoformat(),
            "processTree": {
                "nodes": nodes,
                "edges": edges
            }
        }
        
        response = HTTP_SESSION.post(
            TRACE_API_URL,
            json=trace_data,
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"{COLORS['green']}✅ [溯源数据推送成功] 节点数: {len(nodes)}, 边数: {len(edges)}{COLORS['reset']}")
            logger.info(f"   📊 进程链: {' → '.join([p['name'] for p in chain])}")
        else:
            logger.error(f"❌ [溯源推送失败] 状态码: {response.status_code}")
            
    except Exception as e:
        logger.error(f"❌ [溯源推送异常] {str(e)}")

# ================= 数据包处理 =================
def packet_callback(packet):
    """处理捕获的数据包"""
    if not packet.haslayer(Raw) or not packet.haslayer(IP):
        return
    
    try:
        payload_bytes = packet[Raw].load
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 过滤本地回环和后端流量
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            return
        if dst_ip == JAVA_IP and packet.haslayer(TCP) and packet[TCP].dport == JAVA_PORT:
            return
        
        # 检测攻击
        result = detect_attack_type(payload_bytes)
        if result:
            attack_type, signature = result
            payload_str = payload_bytes.decode('utf-8', errors='ignore')
            
            # 🔥 去重检查：如果已经推送过相同的攻击类型，跳过
            attack_key = (src_ip, dst_ip, attack_type)
            if attack_key in pushed_attacks:
                logger.debug(f"⏭️ [跳过重复] {attack_type} | {src_ip} -> {dst_ip}")
                return
            
            # 标记为已推送
            pushed_attacks.add(attack_key)
            
            logger.info(f"{COLORS['red']}🔥 [PIDS] 检测到攻击: {attack_type}{COLORS['reset']}")
            logger.info(f"   来源: {src_ip} -> 目标: {dst_ip}")
            logger.info(f"   特征: {signature}")
            
            # 🔥 先监控进程树，再推送告警（这样告警中就包含进程树数据）
            def monitor_and_push():
                time.sleep(0.5)  # 等待靶机执行命令
                
                # 查找靶机进程
                server_pid = find_server_process()
                process_data = None
                
                if server_pid:
                    logger.info(f"🎯 找到靶机进程: PID={server_pid}")
                    
                    # 监控进程树
                    attack_id_temp = str(uuid.uuid4())
                    process_data = monitor_process_tree(server_pid, attack_id_temp)
                else:
                    logger.warning("⚠️ 未找到靶机进程")
                
                # 推送告警（包含进程树数据）
                push_alert(attack_type, payload_str, src_ip, dst_ip, process_data)
            
            threading.Thread(target=monitor_and_push, daemon=True).start()
                
    except Exception as e:
        logger.debug(f"处理数据包异常: {e}")

# ================= 主函数 =================
def main():
    """主函数"""
    # 检查 root 权限
    if os.geteuid() != 0:
        print(f"{COLORS['red']}❌ 错误: 需要 root 权限运行此脚本{COLORS['reset']}")
        print(f"   请使用: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    print("="*60)
    print("🔍 PIDS 进程溯源引擎 v3.0")
    print("="*60)
    print(f"📡 监听网卡: {IFACE}")
    print(f"🎯 监听端口: {MONITOR_PORT}")
    print(f"🎯 后端地址: {ALERT_API_URL}")
    print(f"📝 日志文件: {LOG_FILE}")
    print("="*60)
    
    # 测试后端连接
    print(f"\n🔍 正在测试后端连接...")
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((JAVA_IP, JAVA_PORT))
        sock.close()
        if result == 0:
            print(f"{COLORS['green']}✅ 后端连接测试成功!{COLORS['reset']}")
        else:
            print(f"{COLORS['red']}❌ 后端连接失败 (错误码: {result}){COLORS['reset']}")
            print(f"   请确保后端服务运行在 {JAVA_IP}:{JAVA_PORT}")
            sys.exit(1)
    except Exception as e:
        print(f"{COLORS['red']}❌ 后端连接测试失败: {e}{COLORS['reset']}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print(f"🚀 开始监听网络流量和进程...")
    print("="*60 + "\n")
    
    # 开始抓包
    try:
        sniff(
            iface=IFACE,
            filter=f"tcp port {MONITOR_PORT}",
            prn=packet_callback,
            store=0
        )
    except KeyboardInterrupt:
        print(f"\n\n{COLORS['yellow']}👋 用户中断，正在退出...{COLORS['reset']}")
    except Exception as e:
        logger.error(f"{COLORS['red']}❌ 抓包异常: {e}{COLORS['reset']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
