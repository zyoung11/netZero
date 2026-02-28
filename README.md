# netZero - 分布式VPN系统

netZero是一个基于[Nebula](https://github.com/slackhq/nebula)构建的分布式VPN系统，提供安全的点对点网络连接。系统采用客户端-服务器架构，支持三种预设的权限控制。

## 系统架构

### 核心组件

1. **lighthouse** - 服务器端
   
   - 中央协调节点，管理网络拓扑
   - 提供证书颁发和用户管理
   - 运行在具有公网IP的服务器上

2. **netZero** - 客户端
   
   - 用户终端程序，连接VPN网络
   - 支持管理员和普通用户两种角色
   - 提供交互式命令行界面

### 网络拓扑

- **网关IP**: 192.168.100.1 (lighthouse节点)
- **客户端IP范围**: 192.168.100.2-254
- **通信端口**: 4242 (Nebula), 9090 (管理API)

## 快速开始

### 服务器端部署 (lighthouse)

1. **环境要求**
   
   - Linux系统 (需要root权限)
   - 公网IP地址
   - Go 1.25+ 开发环境

2. 下载预编译版本
   
   - Linux: [lighthouse-linux.zip](https://github.com/zyoung11/netZero/releases/latest/download/lighthouse-linux.zip)

3. **安装步骤**
   
   ```bash
   # 克隆项目
   git clone <repository-url>
   cd netZero/lighthouse
   
   # 安装依赖
   go mod tidy
   
   # 编译
   go build .
   
   # 运行初始化
   sudo ./lighthouse run
   ```

4. **系统服务安装**
   
   ```bash
   # 生成服务文件
   ./lighthouse service
   
   # 按照提示安装系统服务
   sudo cp lighthouse.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now lighthouse.service
   ```

### 客户端部署 (netZero)

1. **下载预编译版本**
   
   - Linux: [netZero-linux.zip](https://github.com/zyoung11/netZero/releases/latest/download/netZero-linux.zip)
   - Windows: [netZero-win.zip](https://github.com/zyoung11/netZero/releases/latest/download/netZero-win.zip)

2. **首次使用**
   
   ```bash
   # 管理员初始化
   ./netZero run
   
   # 普通用户加入网络
   ./netZero join
   ```

## 功能特性

### 用户管理

- **三种权限级别**:
  
  - `admin`: 完全访问权限，可生成邀请码
  - `guest`: 受限制的访问权限
  - `untrusted`: 最低权限，仅基础连接

- **邀请系统**: 管理员可生成加密的邀请码，新用户通过邀请码加入网络

### 安全特性

- **端到端加密**: 基于Nebula的WireGuard-like加密
- **证书认证**: 每个用户拥有唯一的客户端证书
- **权限隔离**: 基于组的防火墙规则
- **通信加密**: 管理API使用AES-256加密

## 详细使用指南

### 服务器端命令

```bash
# 启动服务
lighthouse run

# 查看用户列表
lighthouse list

# 安装系统服务
lighthouse service

# 重置所有配置
lighthouse redo

# 显示帮助
lighthouse help
```

### 客户端命令

```bash
# 启动/初始化连接
netZero run

# 通过邀请码加入网络
netZero join

# 生成邀请码 (仅管理员)
netZero invite

# 安装系统服务
netZero service

# 显示分配的IP地址
netZero ip

# 重置所有配置
netZero redo

# 显示帮助
netZero help
```

### 管理员操作流程

1. **服务器端初始化**
   
   ```bash
   sudo ./lighthouse run
   # 输入公网IP和管理密码
   ```

2. **客户端管理员初始化**
   
   ```bash
   ./netZero run
   # 输入服务器公网IP、密码和用户名
   ```

3. **生成用户邀请码**
   
   ```bash
   ./netZero invite
   # 输入用户名、权限级别和有效期
   ```

### 普通用户加入流程

1. **获取邀请码文件** (`Invitation.txt`)
2. **运行加入命令**
   
   ```bash
   ./netZero join
   # 粘贴邀请码内容
   ```
3. **启动连接**
   
   ```bash
   ./netZero run
   ```

## Nebula配置

### Lighthouse

```toml
pki:
  ca: ./config/ca.crt
  cert: ./config/lighthouse.crt
  key: ./config/lighthouse.key

static_host_map:
  "192.168.100.1": ["%s:4242"]

lighthouse:
  am_lighthouse: true
  serve_dns: false

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

cipher: aes

tun:
  disabled: false
  dev: netzero
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: 4242
      proto: any
      host: any

    - port: 9090
      proto: any
      group: admin

    - port: 9090
      proto: any
      group: guest

    - port: 9090
      proto: any
      group: untrusted

    - port: 80
      proto: any
      group: admin

    - port: 80
      proto: any
      group: guest

    - port: 443
      proto: any
      group: admin

    - port: 443
      proto: any
      group: guest

    - port: any
      proto: any
      group: admin

    - port: any
      proto: icmp
      group: any
```

### Node（通用）

```toml
pki:
  ca: ./config/ca.crt
  cert: ./config/%s.crt
  key: ./config/%s.key

static_host_map:
  "192.168.100.1": ["%s:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"

listen:
  host: 0.0.0.0
  port: 0

punchy:
  punch: true
  respond: true

relay:
  am_relay: false
  use_relays: true

cipher: aes

tun:
  dev: netZero
  mtu: 1300

logging:
  level: info
```

### 权限预设

#### Admin

```toml
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: admin

    - port: any
      proto: any
      group: guest
```

#### guest

```toml
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: admin

    - port: any
      proto: any
      group: guest
```

#### untrusted

```toml
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: any
```

## 文件结构

### 服务器端配置

```
config/
├── ca.crt          # CA根证书
├── ca.key          # CA私钥
├── lighthouse.crt  # 服务器证书
├── lighthouse.key  # 服务器私钥
├── config.yml      # Nebula配置文件
└── data.db         # 用户数据库
```

### 客户端配置

```
config/
├── ca.crt          # CA根证书
├── <username>.crt  # 客户端证书
├── <username>.key  # 客户端私钥
├── config.yml      # Nebula配置文件
└── data.db         # 本地配置数据库
```

### 项目结构

```
netZero/
├── lighthouse/     # 服务器端代码
│   ├── bolt/       # 数据库操作
│   ├── result/     # 结果展示组件
│   ├── table/      # 表格组件
│   ├── texts/      # 文本输入组件
│   └── main.go     # 主程序
├── node/           # 客户端代码
│   ├── bolt/       # 数据库操作
│   ├── result/     # 结果展示组件
│   ├── texts/      # 文本输入组件
│   ├── linux.go    # Linux特定实现
│   ├── windows.go  # Windows特定实现
│   └── main.go     # 主程序
├── nebula          # Nebula二进制 (符号链接)
├── nebula-cert     # Nebula证书工具 (符号链接)
└── README.md       # 本文档
```
