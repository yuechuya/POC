# 百易云资管系统 imaRead.make.php SQL注入检测 POC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

**作者**：weichao (围巢)  
**版本**：1.0  
**漏洞类型**：报错注入 (updatexml)  
**影响产品**：百易云资管系统 `imaRead.make.php` 接口

---

## 📌 免责声明

> **本工具仅供授权安全测试、漏洞验证及教育研究使用。**  
> 未经授权使用本工具对目标系统进行扫描、攻击或渗透测试均属违法行为。  
> 使用者须自行承担因滥用工具所产生的一切法律责任。  
> 作者及贡献者不对任何不当使用负责。

---

## 📖 项目介绍

百易云资管系统某版本存在SQL注入漏洞，攻击者可通过 `feeItem[]` 参数构造报错注入，获取数据库敏感信息。  
本工具实现了对该漏洞的快速验证，支持单目标和批量检测，并具备代理、并发控制等功能。

---

## ✨ 功能特点

- ✔ 基于 POST 请求发送注入 Payload，符合实际漏洞场景
- ✔ 自动忽略 SSL 证书验证，支持 HTTPS 自签名站点
- ✔ 支持 HTTP/HTTPS 代理（方便配合 Burp Suite 调试）
- ✔ 多进程并发检测，可自定义进程数
- ✔ 自动保存存在漏洞的 URL 到 `result.txt`
- ✔ 丰富的错误处理，单个目标失败不影响整体扫描

---

## 🔧 安装与依赖

### 环境要求
- Python 3.6 或更高版本

### 安装依赖
克隆或下载项目后，在项目根目录执行：

```bash
pip install -r requirements.txt
```

## 🚀 使用方法

### 基本语法

```
python poc.py [-h] [-u URL] [-f FILE] [-t THREADS] [--proxy PROXY]
```

### 命令行参数说明

| 参数                            | 说明                                                         |
| :------------------------------ | :----------------------------------------------------------- |
| `-h, --help`                    | 显示帮助信息                                                 |
| `-u URL, --url URL`             | 检测单个 URL（需包含协议，如 `http://example.com/imaRead.make.php`） |
| `-f FILE, --file FILE`          | 批量检测文件（每行一个 URL）                                 |
| `-t THREADS, --threads THREADS` | 并发进程数，默认为 10                                        |
| `--proxy PROXY`                 | 指定代理地址（例如 `http://127.0.0.1:7890`）                 |

### 使用示例

**1. 检测单个目标**

```
python poc.py -u "http://192.168.1.100/imaRead.make.php"
```

**2. 批量检测（10个进程）**

```
python poc.py -f urls.txt
```

**3. 自定义并发数（20个进程）**

```
python poc.py -f urls.txt -t 20
```

**4. 通过代理检测（如 Burp Suite 抓包）**

```
python poc.py -u "https://target.com/imaRead.make.php" --proxy http://127.0.0.1:8080
```

------

## 📂 输出结果

存在漏洞的 URL 会实时显示在控制台（标记 `[+]`），并自动追加到当前目录下的 `result.txt` 文件中（每行一个 URL）。

示例输出：

```
[+] http://192.168.1.100/imaRead.make.php 存在漏洞
[-] http://192.168.1.101/imaRead.make.php 不存在漏洞
[!] 请求 http://192.168.1.102/imaRead.make.php 时发生错误: Connection timed out
```
