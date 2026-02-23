#!/usr/bin/env python3
"""
HIDS Agent - 主机入侵检测系统代理
采集本机真实的 CPU、内存、磁盘、网络信息并上报给后端
"""

import os
import sys
import psutil
import requests
import socket
import time
import json
import platform
import subprocess
import ctypes
from datetime import datetime

# ===========================
# 1. 基础配置与路径工具
# ===========================

def get_base_dir():
    """获取脚本运行的基础目录 (兼容 PyInstaller 打包)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# 优先使用环境变量，方便容器/服务器部署
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8985/api/host/monitor/report")
REPORT_INTERVAL = int(os.environ.get("REPORT_INTERVAL", 3))
BLOCKED_IPS_FILE = os.path.join(get_base_dir(), "blocked_ips.json")

def log_message(msg, level="INFO"):
    """记录日志到文件和控制台"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{now}] [{level}] {msg}"
    print(log_line)
    
    # 同时写入日志文件
    try:
        log_file = os.path.join(get_base_dir(), "hids_agent.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    except:
        pass

# ===========================
# 2. IP 与网络工具
# ===========================

def get_local_ip():
    """获取本机真实IP地址"""
    try:
        # 创建UDP socket获取真实出口IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

def get_all_local_ips():
    """获取本机所有网卡的IP地址，用于白名单检查"""
    ips = set()
    ips.add("127.0.0.1")
    ips.add("localhost")
    ips.add("0.0.0.0")
    ips.add("::1")
    
    try:
        for interface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    ips.add(snic.address)
    except:
        pass
        
    try:
        ip = get_local_ip()
        if ip: ips.add(ip)
    except:
        pass
    return ips

# 确定 Host ID
HOST_ID = os.environ.get("HOST_IP", get_local_ip())

def update_blocked_ips(ip, action):
    """更新本地封禁IP列表文件"""
    try:
        blocked_ips = []
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                try:
                    blocked_ips = json.load(f)
                except json.JSONDecodeError:
                    blocked_ips = []
        
        if action == "add":
            if ip not in blocked_ips:
                blocked_ips.append(ip)
        elif action == "remove":
            if ip in blocked_ips:
                blocked_ips.remove(ip)
        
        with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(blocked_ips, f, indent=4)
            
    except Exception as e:
        log_message(f"Failed to update blocked IPs file: {e}", "ERROR")

# ===========================
# 3. 系统信息采集
# ===========================

def get_cpu_model():
    """获取真实的CPU型号"""
    try:
        if platform.system() == "Windows":
            # Windows: 使用wmic命令获取CPU名称
            result = subprocess.run(
                ["wmic", "cpu", "get", "name", "/value"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if line.strip().startswith('Name='):
                    return line.strip().split('=', 1)[1]
        else:
            # Linux: 从/proc/cpuinfo读取
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line:
                        return line.split(':')[1].strip()
    except Exception as e:
        pass
    return "Unknown CPU"

def get_memory_info():
    """获取真实的内存信息"""
    try:
        mem = psutil.virtual_memory()
        total_gb = round(mem.total / (1024**3), 1)
        
        if platform.system() == "Windows":
            # Windows: 尝试获取内存速度
            result = subprocess.run(
                ["wmic", "memorychip", "get", "speed", "/value"],
                capture_output=True, text=True, timeout=5
            )
            speed = "Unknown"
            for line in result.stdout.split('\n'):
                if line.strip().startswith('Speed='):
                    speed = line.strip().split('=', 1)[1]
                    break
            return f"{total_gb}GB RAM @ {speed}MHz"
        
        return f"{total_gb}GB RAM"
    except Exception as e:
        return f"{round(psutil.virtual_memory().total / (1024**3), 1)}GB RAM"

def collect_system_info():
    """采集系统详细信息"""
    # 1. CPU
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_model = get_cpu_model()
    cpu_cores = psutil.cpu_count(logical=True)
    try:
        cpu_freq_info = psutil.cpu_freq()
        cpu_freq_ghz = round(cpu_freq_info.current / 1000, 2) if cpu_freq_info else 0
    except:
        cpu_freq_ghz = 0
    
    # 2. Memory
    memory = psutil.virtual_memory()
    memory_usage = memory.percent
    memory_info = get_memory_info()
    memory_total_gb = round(memory.total / (1024**3), 1)
    memory_used_gb = round(memory.used / (1024**3), 1)
    
    # 3. Disk (Detailed)
    total_disk = 0
    used_disk = 0
    disk_partitions = []
    
    if platform.system() == "Windows":
        for partition in psutil.disk_partitions():
            if 'cdrom' in partition.opts or partition.fstype == '':
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total_disk += usage.total
                used_disk += usage.used
                
                disk_partitions.append({
                    "name": partition.mountpoint.replace("\\", ""),
                    "total": round(usage.total / (1024**3), 1),
                    "used": round(usage.used / (1024**3), 1),
                    "free": round(usage.free / (1024**3), 1),
                    "percent": round(usage.percent, 1),
                    "fstype": partition.fstype
                })
            except:
                continue
    else:
        try:
            disk = psutil.disk_usage('/')
            total_disk = disk.total
            used_disk = disk.used
            disk_partitions.append({
                "name": "/",
                "total": round(disk.total / (1024**3), 1),
                "used": round(disk.used / (1024**3), 1),
                "free": round(disk.free / (1024**3), 1),
                "percent": round(disk.percent, 1),
                "fstype": "ext4"
            })
        except:
            pass
    
    disk_usage = round((used_disk / total_disk) * 100, 1) if total_disk > 0 else 0
    disk_total_gb = total_disk / (1024**3)
    disk_used_gb = used_disk / (1024**3)
    disk_free_gb = (total_disk - used_disk) / (1024**3)
    disk_info = f"{int(disk_used_gb)}GB / {int(disk_total_gb)}GB"
    disk_partitions_json = json.dumps(disk_partitions, ensure_ascii=False)
    
    # 4. Network
    try:
        network_conn = len(psutil.net_connections())
    except:
        network_conn = 0
    
    # 5. File Status (Simplified FIM)
    file_status_list = []
    files_to_watch = [r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\win.ini"] if platform.system() == "Windows" else ["/etc/passwd", "/etc/hosts"]
    for fpath in files_to_watch:
        status = "normal"
        if os.path.exists(fpath):
            if (time.time() - os.path.getmtime(fpath)) < 600:
                status = "modified"
        else:
            status = "missing"
        file_status_list.append({"path": fpath, "status": status})
    
    return {
        "hostId": HOST_ID,
        "cpuUsage": round(cpu_usage, 1),
        "cpuModel": cpu_model,
        "cpuCores": cpu_cores,
        "cpuFreq": cpu_freq_ghz,
        "memoryUsage": round(memory_usage, 1),
        "memoryInfo": memory_info,
        "memoryTotalGb": memory_total_gb,
        "memoryUsedGb": memory_used_gb,
        "networkConn": network_conn,
        "diskUsage": round(disk_usage, 1),
        "diskInfo": disk_info,
        "diskTotalGb": disk_total_gb,
        "diskUsedGb": disk_used_gb,
        "diskFreeGb": disk_free_gb,
        "diskPartitions": disk_partitions_json,
        "fileStatus": json.dumps(file_status_list)
    }

# ===========================
# 4. 指令执行与防御
# ===========================

def execute_command(cmd):
    try:
        log_message(f"Received command: {cmd}")
        if cmd.startswith("BLOCK_IP"):
            ip = cmd.split()[1]
            log_message(f"BLOCKING IP: {ip}", "WARN")
            
            # --- SAFETY CHECK ---
            local_ips = get_all_local_ips()
            if ip in local_ips:
                log_message(f"SAFETY TRIGGERED: Cannot block local IP {ip}!", "WARN")
                return
            # --------------------

            if platform.system() == "Windows":
                rule_name = f"Block_{ip}"
                full_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} profile=any'
                res = subprocess.run(full_cmd, shell=True, capture_output=True)
                
                try:
                    stdout = res.stdout.decode('gbk', errors='replace')
                except:
                    stdout = res.stdout.decode('utf-8', errors='replace')

                if res.returncode == 0:
                    log_message(f"Firewall rule added: {stdout.strip()}")
                    update_blocked_ips(ip, "add")
                else:
                    log_message(f"FAILED to add firewall rule: {stdout.strip()}", "ERROR")

            else:
                full_cmd = f"iptables -A INPUT -s {ip} -j DROP"
                res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
                if res.returncode == 0:
                    log_message("iptables rule added successfully")
                    update_blocked_ips(ip, "add")
                else:
                    log_message(f"FAILED to add iptables rule: {res.stderr}", "ERROR")
        
        elif cmd.startswith("UNBLOCK_IP"):
            ip = cmd.split()[1]
            log_message(f"UNBLOCKING IP: {ip}", "WARN")

            if platform.system() == "Windows":
                rule_name = f"Block_{ip}"
                cmd1 = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                cmd2 = f'netsh advfirewall firewall delete rule name=all remoteip={ip}'
                
                subprocess.run(cmd1, shell=True, capture_output=True)
                res = subprocess.run(cmd2, shell=True, capture_output=True)
                
                try:
                    stdout = res.stdout.decode('gbk', errors='replace')
                except:
                    stdout = res.stdout.decode('utf-8', errors='replace')

                if res.returncode == 0 or "没有" in stdout or "No rules" in stdout:
                    log_message(f"Firewall rule removed: {stdout.strip()}")
                    update_blocked_ips(ip, "remove")
                else:
                    log_message(f"FAILED to remove firewall rule: {stdout.strip()}", "ERROR")

            else:
                full_cmd = f"iptables -D INPUT -s {ip} -j DROP"
                res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
                if res.returncode == 0:
                     log_message("iptables rule removed successfully")
                     update_blocked_ips(ip, "remove")
                else:
                     log_message(f"FAILED to remove iptables rule: {res.stderr}", "ERROR")
                
    except Exception as e:
        log_message(f"Command execution failed: {e}", "ERROR")

# ===========================
# 5. 主循环与守护进程
# ===========================

def main_loop():
    host_ip = HOST_ID
    print(f"""
╔══════════════════════════════════════════════════════╗
║           HIDS Agent - 主机监控代理                  ║
╠══════════════════════════════════════════════════════╣
║  Host ID: {host_ip:<42} ║
║  Backend: {BACKEND_URL:<42} ║
╚══════════════════════════════════════════════════════╝
    """)
    
    log_message("HIDS Agent Started")
    
    consecutive_failures = 0
    
    while True:
        try:
            data = collect_system_info()
            
            # 显示简略信息
            now = datetime.now().strftime("%H:%M:%S")
            print(f"[{now}] CPU:{data['cpuUsage']}% MEM:{data['memoryUsage']}% DISK:{data['diskUsage']}% NET:{data['networkConn']}")
            
            # 上报
            response = requests.post(BACKEND_URL, json=data, timeout=5)
            
            if response.status_code == 200:
                consecutive_failures = 0
                result = response.json()
                # 检查指令
                if result and isinstance(result, dict) and result.get("data") and isinstance(result["data"], dict):
                    inner_data = result["data"]
                    if "commands" in inner_data:
                        for cmd in inner_data["commands"]:
                            execute_command(cmd)
            else:
                consecutive_failures += 1
                print(f"  └─ Report Failed: {response.status_code}")
                
        except Exception as e:
            consecutive_failures += 1
            print(f"  └─ Connection Error: {e}")
            if consecutive_failures >= 10:
                log_message("Too many failures, sleeping 30s...", "WARN")
                time.sleep(30)
                consecutive_failures = 0
        
        time.sleep(REPORT_INTERVAL)

def run_as_daemon():
    """守护进程模式 - 崩溃自动重启"""
    while True:
        try:
            main_loop()
        except KeyboardInterrupt:
            log_message("Agent stopped by user.")
            break
        except Exception as e:
            log_message(f"Main process crashed: {e}, restarting in 5s...", "ERROR")
            time.sleep(5)

if __name__ == "__main__":
    # Windows提权检查
    if platform.system() == "Windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] WARNING: Not running as Administrator. Blocking features may fail.")
        except:
            pass

    run_as_daemon()
