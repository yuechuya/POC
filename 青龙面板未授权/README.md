# 青龙面板未授权RCE漏洞检测工具 

[![License: MIT](https://gcore.jsdelivr.net/gh/yuechuya/Pictures2@main/202607081622187.svg+xml;charset=utf-8)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

**作者**：weichao  
**版本**：1.1  
**影响产品**：青龙面板（qinglong）v2.15.0 及之前版本

---

## ⚠️ 免责声明

> 本工具仅供授权安全测试、漏洞验证及教育研究使用。  
> 未经授权使用本工具对目标系统进行扫描、攻击或渗透测试均属违法行为。  
> 使用者须自行承担因滥用工具所产生的一切法律责任。

---

## 📖 漏洞简介

青龙面板存在未授权远程代码执行漏洞，攻击者可通过构造特殊请求，利用 `/api/system/command-run` 接口执行任意系统命令。  
本工具通过发送包含 `id` 命令的 PUT 请求，根据响应中是否包含 `uid=` 和 `gid=` 来判断漏洞存在。

---

## ✨ 功能特点

- 单目标和批量检测支持
- 可自定义检测命令（`--cmd`）
- 可自定义并发线程数
- 支持 HTTP/HTTPS 代理
- 自动重试机制，提高稳定性
- 可选健康检查（判断是否为青龙面板）
- 调试模式（`--debug`）输出详细日志
- 结果自动保存至文件

---

## 🔧 安装与使用

### 环境要求
- Python 3.6 及以上

### 安装依赖
```bash
pip install -r requirements.txt
```

### 基本用法

```
python poc.py [-h] [-u URL] [-f FILE] [-t THREADS] [-o OUTPUT] [--timeout SECONDS] [--cmd COMMAND] [--proxy PROXY] [--debug] [--no-health]
```

### 参数说明

| 参数          | 说明                                           |
| :------------ | :--------------------------------------------- |
| `-u URL`      | 检测单个目标（如 `http://192.168.1.100:5700`） |
| `-f FILE`     | 批量检测文件（每行一个URL）                    |
| `-t THREADS`  | 并发线程数，默认20                             |
| `-o OUTPUT`   | 输出文件名，默认 `success.txt`                 |
| `--timeout`   | 请求超时秒数，默认5                            |
| `--cmd`       | 自定义检测命令，默认 `id`                      |
| `--proxy`     | 代理地址，如 `http://127.0.0.1:7890`           |
| `--debug`     | 开启调试输出                                   |
| `--no-health` | 跳过健康检查（/api/health）                    |

### 使用示例

#### 1. 检测单个目标

```
python poc.py -u http://192.168.1.100:5700
```

#### 2. 批量检测（使用默认参数）

```
python poc.py -f urls.txt
```

#### 3. 自定义命令（如 whoami）和线程数

```
python poc.py -f urls.txt --cmd "whoami" -t 30
```

#### 4. 使用代理并开启调试

```
python poc.py -u http://target.com --proxy http://127.0.0.1:8080 --debug
```

#### 5. 跳过健康检查（针对非标准部署）

```
python poc.py -f urls.txt --no-health
```

------

## 📂 输出示例

控制台输出：

```
[*] 共加载 100 个目标，开始扫描...
[INFO] http://192.168.1.10:5700 -> 健康检查通过（青龙面板特征）
[!] 发现漏洞目标：http://192.168.1.10:5700
[INFO] http://192.168.1.11:5700 -> 健康检查返回 404，可能非青龙面板
扫描进度: 100%|████████████| 100/100 [00:15<00:00,  6.5目标/s]

[+] 扫描完成，发现 3 个漏洞目标，已保存至 success.txt
```

成功保存的 `success.txt` 内容示例：

```
http://192.168.1.10:5700
http://192.168.1.20:5700
http://192.168.1.30:5700
```