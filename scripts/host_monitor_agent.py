#!/usr/bin/env python3
"""
御链天鉴 - 本地主机监控Agent
收集真实的CPU、内存、磁盘、网络数据并上报到后端
"""

import psutil
import socket
import json
import time
import requests
from datetime import datetime

# 配置
BACKEND_URL = "http://localhost:8985"
HOST_ID = None  # 自动获取本机IP
INTERVAL = 3  # 采集间隔（秒）

def get_local_ip():
    """获取本机IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_cpu_info():
    """获取CPU信息"""
    try:
        freq = psutil.cpu_freq()
        return {
            "usage": psutil.cpu_percent(interval=1),
            "cores": psutil.cpu_count(logical=True),
            "freq": round(freq.current / 1000, 2) if freq else 0,
            "model": get_cpu_model()
        }
    except Exception as e:
        print(f"获取CPU信息失败: {e}")
        return {"usage": 0, "cores": 0, "freq": 0, "model": "Unknown"}

def get_cpu_model():
    """获取CPU型号"""
    import platform
    if platform.system() == "Windows":
        import subprocess
        try:
            # 方法1: 使用wmic
            result = subprocess.run(
                ["wmic", "cpu", "get", "name"],
                capture_output=True, text=True, timeout=5, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
            if len(lines) > 1:
                return lines[1]
        except:
            pass
        
        try:
            # 方法2: 使用注册表
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            return cpu_name.strip()
        except:
            pass
    
    # 方法3: 使用platform
    proc = platform.processor()
    if proc and proc != "":
        return proc
    
    return "Intel/AMD Processor"

def get_memory_type():
    """获取内存类型 DDR4/DDR5"""
    import platform
    if platform.system() == "Windows":
        import subprocess
        try:
            result = subprocess.run(
                ["wmic", "memorychip", "get", "SMBIOSMemoryType"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip() and l.strip().isdigit()]
            if lines:
                mem_type_code = int(lines[0])
                # SMBIOS Memory Type codes
                types = {20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 34: "DDR5"}
                return types.get(mem_type_code, "DDR4")
        except:
            pass
    return "DDR4"

def get_memory_info():
    """获取内存信息"""
    try:
        mem = psutil.virtual_memory()
        total_gb = round(mem.total / (1024**3), 1)
        used_gb = round(mem.used / (1024**3), 1)
        
        # 获取内存类型
        mem_type = get_memory_type()
        
        return {
            "usage": mem.percent,
            "total_gb": total_gb,
            "used_gb": used_gb,
            "info": f"{mem_type} {total_gb:.0f}GB"
        }
    except Exception as e:
        print(f"获取内存信息失败: {e}")
        return {"usage": 0, "total_gb": 0, "used_gb": 0, "info": "Unknown"}

def get_disk_info():
    """获取磁盘信息"""
    try:
        partitions = []
        total_used = 0
        total_size = 0
        
        for part in psutil.disk_partitions():
            if 'cdrom' in part.opts or part.fstype == '':
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partitions.append({
                    "name": part.device.replace("\\", "").replace(":", ""),
                    "fstype": part.fstype,
                    "total": round(usage.total / (1024**3), 0),
                    "used": round(usage.used / (1024**3), 0),
                    "free": round(usage.free / (1024**3), 0),
                    "percent": usage.percent
                })
                total_used += usage.used
                total_size += usage.total
            except:
                continue
        
        return {
            "usage": round(total_used / total_size * 100, 1) if total_size > 0 else 0,
            "total_gb": round(total_size / (1024**3), 0),
            "used_gb": round(total_used / (1024**3), 0),
            "free_gb": round((total_size - total_used) / (1024**3), 0),
            "info": f"{round(total_used / (1024**3), 0)}GB/{round(total_size / (1024**3), 0)}GB",
            "partitions": partitions
        }
    except Exception as e:
        print(f"获取磁盘信息失败: {e}")
        return {"usage": 0, "total_gb": 0, "used_gb": 0, "free_gb": 0, "info": "0/0GB", "partitions": []}

def get_network_connections():
    """获取网络连接数"""
    try:
        return len(psutil.net_connections())
    except:
        return 0

def get_file_status():
    """获取核心文件状态"""
    import os
    files_to_check = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\cmd.exe",
    ]
    
    status = []
    for filepath in files_to_check:
        try:
            if os.path.exists(filepath):
                stat = os.stat(filepath)
                # 简化路径显示
                display_path = filepath.replace("C:\\Windows\\System32\\", "..\\")
                display_path = display_path.replace("C:\\Windows\\", "Win\\")
                status.append({
                    "path": display_path,
                    "status": "normal",
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%m-%d %H:%M")
                })
            else:
                status.append({"path": filepath, "status": "missing"})
        except PermissionError:
            status.append({"path": filepath.split("\\")[-1], "status": "protected"})
        except:
            status.append({"path": filepath.split("\\")[-1], "status": "error"})
    
    return status

def collect_data():
    """收集所有监控数据"""
    cpu = get_cpu_info()
    mem = get_memory_info()
    disk = get_disk_info()
    
    return {
        "hostId": HOST_ID,
        "cpuUsage": float(cpu["usage"]),
        "cpuModel": cpu["model"],
        "cpuCores": int(cpu["cores"]),
        "cpuFreq": float(cpu["freq"]),
        "memoryUsage": float(mem["usage"]),
        "memoryInfo": mem["info"],
        "memoryTotalGb": float(mem["total_gb"]),
        "memoryUsedGb": float(mem["used_gb"]),
        "networkConn": int(get_network_connections()),
        "diskUsage": float(disk["usage"]),
        "diskInfo": disk["info"],
        "diskTotalGb": float(disk["total_gb"]),
        "diskUsedGb": float(disk["used_gb"]),
        "diskFreeGb": float(disk["free_gb"]),
        "diskPartitions": json.dumps(disk["partitions"]),
        "fileStatus": json.dumps(get_file_status())
    }

def send_to_backend(data):
    """发送数据到后端"""
    try:
        # 先登录获取token
        login_resp = requests.post(
            f"{BACKEND_URL}/api/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        token = login_resp.json().get("data", {}).get("token")
        
        if not token:
            print("登录失败，无法获取token")
            return False
        
        # 发送监控数据
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.post(
            f"{BACKEND_URL}/api/host/monitor/report",
            json=data,
            headers=headers,
            timeout=5
        )
        
        if resp.status_code == 200:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 数据上报成功 - CPU:{data['cpuUsage']:.1f}% 内存:{data['memoryUsage']:.1f}%")
            return True
        else:
            print(f"上报失败: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        print(f"发送失败: {e}")
        return False

def main():
    global HOST_ID
    HOST_ID = get_local_ip()
    
    print("=" * 50)
    print("  御链天鉴 - 本地主机监控Agent")
    print("=" * 50)
    print(f"主机IP: {HOST_ID}")
    print(f"后端地址: {BACKEND_URL}")
    print(f"采集间隔: {INTERVAL}秒")
    print("=" * 50)
    print("开始采集数据... (Ctrl+C 停止)")
    print()
    
    while True:
        try:
            data = collect_data()
            send_to_backend(data)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            print("\n停止监控")
            break
        except Exception as e:
            print(f"错误: {e}")
            time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
