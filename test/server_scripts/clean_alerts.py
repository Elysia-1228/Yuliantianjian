# -*- coding: utf-8 -*-
"""
清除指定 IP 的告警数据
用于测试前清空数据库
"""
import pymysql
import sys

# ================= 配置区域 =================
DB_HOST = "localhost"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "z2392099751"
DB_NAME = "net_safe"
# ===========================================

def clean_alerts_by_ip(source_ip):
    """清除指定源 IP 的所有告警数据"""
    try:
        # 连接数据库
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        
        # 查询要删除的记录数
        cursor.execute(
            "SELECT COUNT(*) FROM potential_threat_alert WHERE source_ip = %s",
            (source_ip,)
        )
        count = cursor.fetchone()[0]
        
        if count == 0:
            print(f"✅ 没有找到源 IP 为 {source_ip} 的告警记录")
            return
        
        print(f"🔍 找到 {count} 条源 IP 为 {source_ip} 的告警记录")
        
        # 确认删除
        confirm = input(f"❓ 确认删除这 {count} 条记录？(y/n): ").strip().lower()
        if confirm != 'y':
            print("❌ 取消删除")
            return
        
        # 删除记录
        cursor.execute(
            "DELETE FROM potential_threat_alert WHERE source_ip = %s",
            (source_ip,)
        )
        conn.commit()
        
        print(f"✅ 成功删除 {cursor.rowcount} 条记录")
        
        cursor.close()
        conn.close()
        
    except pymysql.Error as e:
        print(f"❌ 数据库错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 异常: {e}")
        sys.exit(1)

def clean_all_alerts():
    """清除所有告警数据"""
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        
        # 查询总记录数
        cursor.execute("SELECT COUNT(*) FROM potential_threat_alert")
        count = cursor.fetchone()[0]
        
        if count == 0:
            print(f"✅ 数据库中没有告警记录")
            return
        
        print(f"🔍 数据库中共有 {count} 条告警记录")
        
        # 确认删除
        confirm = input(f"❓ 确认删除所有 {count} 条记录？(y/n): ").strip().lower()
        if confirm != 'y':
            print("❌ 取消删除")
            return
        
        # 删除所有记录
        cursor.execute("DELETE FROM potential_threat_alert")
        conn.commit()
        
        print(f"✅ 成功删除 {cursor.rowcount} 条记录")
        
        cursor.close()
        conn.close()
        
    except pymysql.Error as e:
        print(f"❌ 数据库错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 异常: {e}")
        sys.exit(1)

def main():
    """主函数"""
    print("="*60)
    print("🗑️  告警数据清理工具")
    print("="*60)
    print("1. 清除指定 IP 的告警")
    print("2. 清除所有告警")
    print("q. 退出")
    print("="*60)
    
    choice = input("👉 选择: ").strip()
    
    if choice == '1':
        ip = input("请输入要清除的源 IP (例如: 10.10.18.28): ").strip()
        if ip:
            clean_alerts_by_ip(ip)
        else:
            print("❌ IP 地址不能为空")
    elif choice == '2':
        clean_all_alerts()
    elif choice.lower() == 'q':
        print("👋 退出")
    else:
        print("❌ 无效选择")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 用户中断")
