"""
NIDS数据清理脚本
功能：删除数据库中NIDS相关数据，仅保留IP为10.138.50.151的记录
涉及表：potential_threat_alert, threat_traffic_stat
"""
import pymysql
import sys

# 数据库配置
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'z2392099751',
    'database': 'net_safe',
    'charset': 'utf8mb4'
}

KEEP_IP = '10.138.50.151'


def main():
    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()

    try:
        # 1. 查看清理前的数据量
        cursor.execute("SELECT COUNT(*) FROM potential_threat_alert")
        alert_total = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM potential_threat_alert "
            "WHERE source_ip = %s OR target_ip = %s",
            (KEEP_IP, KEEP_IP)
        )
        alert_keep = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_traffic_stat")
        stat_total = cursor.fetchone()[0]

        print(f"=== 清理前统计 ===")
        print(f"potential_threat_alert: 共 {alert_total} 条, 保留 {alert_keep} 条 (IP: {KEEP_IP})")
        print(f"threat_traffic_stat:    共 {stat_total} 条, 保留 0 条 (无 {KEEP_IP} 数据)")
        print(f"将删除: {alert_total - alert_keep + stat_total} 条记录")
        print()

        confirm = input("确认执行清理? (输入 yes 确认): ")
        if confirm.strip().lower() != 'yes':
            print("已取消操作。")
            sys.exit(0)

        # 2. 执行清理
        cursor.execute(
            "DELETE FROM potential_threat_alert "
            "WHERE source_ip != %s AND target_ip != %s",
            (KEEP_IP, KEEP_IP)
        )
        alert_deleted = cursor.rowcount

        cursor.execute("DELETE FROM threat_traffic_stat")
        stat_deleted = cursor.rowcount

        conn.commit()

        # 3. 验证结果
        cursor.execute("SELECT COUNT(*) FROM potential_threat_alert")
        alert_remaining = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_traffic_stat")
        stat_remaining = cursor.fetchone()[0]

        print(f"\n=== 清理完成 ===")
        print(f"potential_threat_alert: 删除 {alert_deleted} 条, 剩余 {alert_remaining} 条")
        print(f"threat_traffic_stat:    删除 {stat_deleted} 条, 剩余 {stat_remaining} 条")

    except Exception as e:
        conn.rollback()
        print(f"执行出错，已回滚: {e}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    main()
