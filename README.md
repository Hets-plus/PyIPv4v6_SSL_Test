# PyIPv4v6_SSL_Test

一个功能强大的 SSL/TLS 测试工具，支持多种协议版本和认证模式，可在 Windows 上作为服务运行。

## 功能特点

### 核心功能
- **SSL/TLS 服务器**：支持 IPv4 和 IPv6，可配置端口、SSL 版本、认证模式
- **SSL/TLS 客户端**：支持连接到服务器，可配置认证模式和 SSL 版本
- **Windows 服务支持**：可作为系统服务安装和运行，支持自动启动
- **多种运行模式**：图形界面模式、命令行模式、服务模式

### 支持的协议
- SSL 2.0
- SSL 3.0
- TLS 1.0
- TLS 1.1
- TLS 1.2

### 认证模式
- **单向认证**：仅服务器验证
- **双向认证**：服务器和客户端互相验证

### 服务器功能
- 支持自动回复客户端消息
- 支持透明模式（回显客户端消息）和数据模式（发送预设数据）
- 详细的连接日志和数据传输统计
- 支持配置证书和密钥路径

### 客户端功能
- 支持连接到指定主机和端口
- 支持配置客户端证书和密钥
- 支持 CA 证书验证
- 详细的连接和数据传输日志

### 服务管理
- 支持安装、卸载、启动、停止服务
- 支持配置服务名称、显示名称、启动模式
- 支持配置运行模式（server/client/both）
- 详细的服务运行日志

## 快速开始

### 图形界面模式
1. 直接运行 `main.py`：
   ```bash
   python main.py
   ```
2. 在界面中配置服务器或客户端参数
3. 点击 "Listen" 启动服务器，或点击 "Connect" 连接到服务器

### 命令行模式
1. 运行服务器：
   ```bash
   python main.py --headless server --config tls_config.json
   ```
2. 运行客户端：
   ```bash
   python main.py --headless client --config tls_config.json
   ```
3. 运行服务器和客户端：
   ```bash
   python main.py --headless both --config tls_config.json
   ```

### Windows 服务模式
1. 以管理员身份运行 PowerShell
2. 安装服务：
   ```powershell
   .\ssl_windows_service.ps1 -Action install -Mode server -Config tls_config.json
   ```
3. 启动服务：
   ```powershell
   .\ssl_windows_service.ps1 -Action start
   ```
4. 停止服务：
   ```powershell
   .\ssl_windows_service.ps1 -Action stop
   ```
5. 卸载服务：
   ```powershell
   .\ssl_windows_service.ps1 -Action uninstall
   ```

## 配置文件说明

配置文件默认为 `tls_config.json`，包含以下主要配置项：

### 服务器配置
- `port`：服务器端口，默认为 8443
- `use_ipv6`：是否使用 IPv6，默认为 false
- `ssl_version`：SSL 版本，可选值：Default, SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2
- `auth_mode`：认证模式，可选值：OneWay, TwoWay
- `server_cert`：服务器证书路径
- `server_key`：服务器密钥路径
- `ca_cert`：CA 证书路径（双向认证时需要）
- `auto_reply`：是否自动回复，默认为 true
- `data_mode`：数据模式，可选值：Transparent, Data

### 客户端配置
- `host`：服务器主机，默认为 127.0.0.1
- `port`：服务器端口，默认为 8443
- `auth_mode`：认证模式，可选值：OneWay, TwoWay
- `client_cert`：客户端证书路径（双向认证时需要）
- `client_key`：客户端密钥路径（双向认证时需要）
- `ca_cert`：CA 证书路径
- `ssl_version`：SSL 版本，可选值：Default, SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2

## 证书配置

### 生成自签名证书
1. 使用 OpenSSL 生成服务器证书和密钥：
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```
2. 生成客户端证书和密钥：
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout client.key -out client.crt -days 365 -nodes
   ```

### 配置证书路径
在 `tls_config.json` 中配置证书路径：
- 服务器模式：设置 `server_cert` 和 `server_key`
- 双向认证：设置 `ca_cert`（服务器和客户端）和 `client_cert`、`client_key`（客户端）

## 日志管理

- 日志默认存储在 `logs` 目录中
- 可通过 `--log-dir` 参数指定自定义日志目录
- 服务模式下，日志存储在配置的日志目录中

## 常见问题

### 服务安装失败
- 确保以管理员身份运行 PowerShell
- 确保已安装 pywin32 模块：`pip install pywin32`
- 检查 Python 路径是否正确

### 连接失败
- 检查服务器是否已启动
- 检查端口是否正确
- 检查防火墙设置
- 检查证书配置是否正确

### 证书验证失败
- 确保使用正确的证书和密钥
- 双向认证时确保 CA 证书配置正确
- 检查证书是否过期

## 依赖项

- Python 2.7（推荐：要支持SSLv2.0、SSLv3.0、TLSv1需要该版本）
- Tkinter（图形界面模式）
- pywin32（服务模式）
- OpenSSL（证书生成）

## 许可证

MIT License

## 支持这个项目
如果你觉得这个项目对你有帮助，请考虑扫描二维码赞助，感谢您的支持！
|微信点赞 | 支付宝点赞 |
|:---:|:---:
| <img src="https://github.com/Hets-plus/PyIPv4v6_SSL_Test/blob/main/img/wechat.jpg?raw=true" width="300" title="微信支付"/> | <img src="https://github.com/Hets-plus/PyIPv4v6_SSL_Test/blob/main/img/alipay.jpg?raw=true" width="300" title="支付宝支付"/> |