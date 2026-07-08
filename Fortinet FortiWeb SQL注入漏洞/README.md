# 福建科立讯通信 指挥调度管理平台 logout.php SQL注入 POC (XVE-2025-25869)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

**作者**：weichao (围巢)  
**版本**：1.0  
**漏洞编号**：XVE-2025-25869  
**漏洞类型**：时间盲注 (Time-based Blind SQL Injection)  
**影响产品**：福建科立讯通信有限公司 指挥调度管理平台

---

## 📌 免责声明

> **本工具仅供授权安全测试、漏洞验证及教育研究使用。**  
> 未经授权使用本工具对目标系统进行扫描、攻击或渗透测试均属违法行为。  
> 使用者须自行承担因滥用工具所产生的一切法律责任。  
> 作者及贡献者不对任何不当使用负责。

---

## 📖 漏洞介绍

福建科立讯通信有限公司指挥调度管理平台的 `/custom/zx/logout.php` 接口存在SQL注入漏洞[reference:0][reference:1]。攻击者可通过构造恶意SQL语句，利用时间盲注方式获取数据库敏感信息，甚至在高权限情况下向服务器写入木马，进一步获取系统权限[reference:2]。

本POC通过发送包含 `SLEEP()` 函数的SQL注入语句，根据响应延迟判断漏洞是否存在。

---

## ✨ 功能特点

- ✔ 基于时间盲注检测，准确且无破坏性
- ✔ 自动忽略 SSL 证书验证，支持 HTTPS 站点
- ✔ 支持 HTTP/HTTPS 代理（方便配合 Burp Suite 调试）
- ✔ 多进程并发检测，可自定义进程数
- ✔ 自动保存存在漏洞的 URL 到 `result.txt`
- ✔ 可自定义 SLEEP 秒数，适应不同网络环境
- ✔ 完善的错误处理，单个目标失败不影响整体扫描

---

## 🔧 安装与依赖

### 环境要求
- Python 3.6 或更高版本

### 安装依赖
```bash
pip install -r requirements.txt
```

## 🚀 使用方法

### 基本语法

```
python poc.py [-h] [-u URL] [-f FILE] [-t THREADS] [--proxy PROXY] [--sleep SECONDS]
```

### 命令行参数说明

| 参数                            | 说明                                         |
| :------------------------------ | :------------------------------------------- |
| `-h, --help`                    | 显示帮助信息                                 |
| `-u URL, --url URL`             | 检测单个 URL（只需提供域名/IP）              |
| `-f FILE, --file FILE`          | 批量检测文件（每行一个 URL）                 |
| `-t THREADS, --threads THREADS` | 并发进程数，默认为 10                        |
| `--proxy PROXY`                 | 指定代理地址（例如 `http://127.0.0.1:7890`） |
| `--sleep SECONDS`               | SLEEP 秒数，默认为 8                         |

### 使用示例

**1. 检测单个目标**

```
python poc.py -u "http://192.168.1.100"
```

**2. 批量检测（10个进程）**

```
python poc.py -f urls.txt
```

**3. 自定义并发数（20个进程）**

```
python poc.py -f urls.txt -t 20
```

**4. 自定义 SLEEP 秒数（5秒）**

```
python poc.py -u "http://192.168.1.100" --sleep 5
```

**5. 通过代理检测**

```
python poc.py -u "https://target.com" --proxy http://127.0.0.1:8080
```

------

## 📂 输出结果

存在漏洞的 URL 会实时显示在控制台（标记 `[+]`），并自动追加到当前目录下的 `result.txt` 文件中。

示例输出：

```
[+] http://192.168.1.100/custom/zx/logout.php 存在漏洞 (正常: 0.05s, 注入: 8.12s, 延迟: 8.07s)
[-] http://192.168.1.101/custom/zx/logout.php 不存在漏洞 (正常: 0.04s, 注入: 0.06s, 延迟: 0.02s)
[+] http://192.168.1.102/custom/zx/logout.php 可能存在漏洞 (请求超时，SLEEP执行)
```

