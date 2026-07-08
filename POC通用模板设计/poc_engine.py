#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
import argparse
import sys
import os
import json
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urljoin, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
+------------------+
|     weichao      |
|   Security Lab   |
+------------------+
[*] 通用POC检测引擎 v1.0
[*] 作者: weichao
"""

class POCEngine:
    def __init__(self, config_file, timeout=10, proxy=None, debug=False):
        self.config = self._load_config(config_file)
        self.timeout = timeout
        self.debug = debug
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.results = []

    def _load_config(self, config_file):
        """加载POC配置文件"""
        with open(config_file, 'r', encoding='utf-8') as f:
            if config_file.endswith('.json'):
                return json.load(f)
            elif config_file.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f)
            else:
                # 尝试JSON解析
                try:
                    return json.load(f)
                except:
                    return yaml.safe_load(f)

    def _send_request(self, base_url, poc_config):
        """根据配置发送请求"""
        method = poc_config.get('method', 'GET').upper()
        path = poc_config.get('path', '')
        headers = poc_config.get('headers', {})
        params = poc_config.get('params', {})
        data = poc_config.get('data', {})
        json_data = poc_config.get('json_data', {})
        
        # 拼接完整URL
        full_url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
        
        # 构造请求参数
        req_kwargs = {
            'timeout': self.timeout,
            'verify': False,
            'proxies': self.proxy,
            'allow_redirects': poc_config.get('allow_redirects', False)
        }
        
        # 设置Headers
        if headers:
            req_kwargs['headers'] = headers
        
        # 根据方法发送请求
        if method == 'GET':
            req_kwargs['params'] = params
            response = requests.get(full_url, **req_kwargs)
        elif method == 'POST':
            req_kwargs['data'] = data
            if json_data:
                req_kwargs['json'] = json_data
            response = requests.post(full_url, **req_kwargs)
        elif method == 'PUT':
            req_kwargs['data'] = data
            if json_data:
                req_kwargs['json'] = json_data
            response = requests.put(full_url, **req_kwargs)
        elif method == 'DELETE':
            response = requests.delete(full_url, **req_kwargs)
        else:
            response = requests.get(full_url, **req_kwargs)
        
        return response

    def _check_vulnerable(self, response, poc_config):
        """根据配置判断是否存在漏洞"""
        check_type = poc_config.get('check_type', 'status_code')
        
        if check_type == 'status_code':
            expected = poc_config.get('expected_status', 200)
            return response.status_code == expected
        
        elif check_type == 'keyword':
            keyword = poc_config.get('keyword', '')
            return keyword in response.text
        
        elif check_type == 'regex':
            import re
            pattern = poc_config.get('regex_pattern', '')
            return re.search(pattern, response.text, re.IGNORECASE) is not None
        
        elif check_type == 'time_based':
            # 时间盲注检测（需要比较正常请求和注入请求的响应时间）
            return poc_config.get('time_elapsed', 5) < 0  # 由外部处理
        
        elif check_type == 'header':
            header_name = poc_config.get('header_name', '')
            header_value = poc_config.get('header_value', '')
            return response.headers.get(header_name) == header_value
        
        elif check_type == 'not_keyword':
            keyword = poc_config.get('keyword', '')
            return keyword not in response.text
        
        else:
            return response.status_code == 200

    def _time_based_check(self, base_url, poc_config):
        """时间盲注检测"""
        normal_path = poc_config.get('normal_path', poc_config.get('path', ''))
        inject_path = poc_config.get('inject_path', '')
        sleep_seconds = poc_config.get('sleep_seconds', 5)
        
        # 获取基线响应时间
        try:
            start = time.time()
            normal_config = poc_config.copy()
            normal_config['path'] = normal_path
            self._send_request(base_url, normal_config)
            normal_time = time.time() - start
        except:
            normal_time = 0.1
        
        # 发送注入请求
        try:
            start = time.time()
            inject_config = poc_config.copy()
            inject_config['path'] = inject_path
            self._send_request(base_url, inject_config)
            inject_time = time.time() - start
        except:
            inject_time = 0
        
        # 判断是否延迟
        return (inject_time - normal_time) > (sleep_seconds - 1)

    def check_single(self, url, vuln_name=None):
        """检测单个目标"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        url = url.rstrip('/')
        
        # 遍历所有POC配置
        pocs = self.config.get('pocs', [self.config])
        for poc_config in pocs:
            vuln_name = poc_config.get('name', '未知漏洞')
            
            if self.debug:
                print(f"[DEBUG] 检测 {url} - {vuln_name}")
            
            # 时间盲注特殊处理
            if poc_config.get('check_type') == 'time_based':
                if self._time_based_check(url, poc_config):
                    return url, True, vuln_name
                continue
            
            try:
                response = self._send_request(url, poc_config)
                if self._check_vulnerable(response, poc_config):
                    return url, True, vuln_name
                else:
                    if self.debug:
                        print(f"[DEBUG] {url} - {vuln_name}: 未命中 (状态码 {response.status_code})")
            except requests.exceptions.RequestException as e:
                if self.debug:
                    print(f"[DEBUG] {url} - {vuln_name}: 请求失败 {e}")
                continue
        
        return url, False, ''

    def scan(self, targets):
        """批量扫描"""
        print(f"[*] 加载配置: {len(self.config.get('pocs', [1]))} 个POC规则")
        print(f"[*] 共 {len(targets)} 个目标，开始扫描...")
        
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.check_single, url): url for url in targets}
            with tqdm(total=len(targets), desc="扫描进度") as pbar:
                for future in as_completed(futures):
                    url, is_vuln, name = future.result()
                    if is_vuln:
                        results.append(url)
                        tqdm.write(f"[+] {url} -> 存在漏洞: {name}")
                    pbar.update(1)
        
        return results

    def save_results(self, output_file):
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.results))


def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="通用POC检测引擎")
    parser.add_argument('-c', '--config', type=str, required=True, help='POC配置文件 (JSON/YAML)')
    parser.add_argument('-u', '--url', type=str, help='单个目标URL')
    parser.add_argument('-f', '--file', type=str, help='批量目标文件')
    parser.add_argument('-o', '--output', type=str, default='success.txt', help='结果输出文件')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='超时时间(秒)')
    parser.add_argument('--proxy', type=str, help='代理地址')
    parser.add_argument('--debug', action='store_true', help='调试模式')
    args = parser.parse_args()
    
    # 加载目标
    targets = []
    if args.url:
        targets = [args.url]
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print("[!] 请指定 -u 或 -f 参数")
        sys.exit(1)
    
    # 初始化引擎
    engine = POCEngine(args.config, args.timeout, args.proxy, args.debug)
    
    # 执行扫描
    results = engine.scan(targets)
    
    # 保存结果
    if results:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(results))
        print(f"\n[+] 发现 {len(results)} 个漏洞目标，已保存至 {args.output}")
    else:
        print("\n[-] 未发现漏洞目标")


if __name__ == "__main__":
    main()