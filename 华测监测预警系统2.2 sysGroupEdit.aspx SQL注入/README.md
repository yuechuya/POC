# 某管理系统 sysGroupEdit.aspx SQL注入检测POC (UNION)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**作者**：weichao  
**版本**：1.0  
**漏洞类型**：联合查询注入 (UNION-based SQL Injection)  
**影响参数**：`id`  
**检测原理**：利用UNION SELECT在响应中注入特征字符串，通过内容匹配判断漏洞存在。

---

## ⚠️ 免责声明

> 本工具仅供授权安全测试、漏洞验证及教育研究使用。  
> 未经授权使用本工具对目标系统进行扫描或攻击属违法行为。  
> 使用者须自行承担一切法律责任。

---

## 📖 漏洞简介

目标系统 `/Web/SysManage/sysGroupEdit.aspx` 页面的 `id` 参数存在SQL注入漏洞，攻击者可利用UNION查询获取数据库敏感信息。

---

## 🔧 安装与使用

### 环境要求
- Python 3.6+

### 安装依赖
```bash
pip install -r requirements.txt
```

### 参数说明

| 参数         | 说明                                           |
| :----------- | :--------------------------------------------- |
| `-u URL`     | 检测单个目标（如 `http://192.168.1.100:8001`） |
| `-f FILE`    | 批量检测文件，每行一个URL                      |
| `-t THREADS` | 并发线程数，默认10                             |
| `--timeout`  | 请求超时时间（秒），默认10                     |
| `--proxy`    | 代理地址（如 `http://127.0.0.1:7890`）         |
| `--debug`    | 开启调试输出                                   |
| `-o OUTPUT`  | 结果输出文件，默认 `success.txt`               |

### 使用示例

#### 1. 检测单个目标

```
python poc.py -u http://124.71.143.18:8001
```

#### 2. 批量检测

```
python poc.py -f urls.txt -t 20
```

#### 3. 使用代理并开启调试

```
python poc.py -u http://target.com --proxy http://127.0.0.1:7890 --debug
```

------

## 📂 输出示例

控制台输出：

```
[+] http://124.71.143.18:8001 -> 存在漏洞 (响应包含特征字符串 'VULN')
[-] http://192.168.1.2:8001 -> 未发现漏洞
```

`success.txt` 内容：

```
http://124.71.143.18:8001
```