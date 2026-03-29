# secssh

[English](./README.md) | **中文**

`secssh` 是一个使用 Go 构建的加密 SSH 工作区管理器。

它会把 SSH 配置、私钥和可选敏感信息统一存放到加密保险库中，并把实际连接行为交给系统自带的 OpenSSH。

## 为什么使用 secssh

日常管理 SSH 通常会把 `ssh_config`、私钥和密码分散在本地多个文件里。`secssh` 用一个保险库把这些内容收拢起来，并提供统一的 CLI 来管理主机、密钥和认证流程，同时又不替换 OpenSSH 本身。

## 核心特性

- 将以下内容加密存放在 `~/.secssh/vault.enc`：
  - 完整的 `ssh_config`
  - 私钥
  - 公钥部分，方便执行公钥复制等流程
  - secrets/密码
  - 按主机配置的认证策略和元数据
  - 主机连接历史
- 与 OpenSSH 兼容的运行时：
  - 不自行实现 SSH 协议
  - 在运行时临时生成配置和密钥文件
  - 支持 `IdentityFile secssh://keys/<name>` 间接引用
- 灵活的密码学配置：
  - KDF：`argon2id`（默认）、`pbkdf2-sha256`
  - Cipher：`aes-256-gcm`（默认）、`xchacha20-poly1305`
  - 修改密码或加密算法时会执行完整重加密
- 主机与认证管理：
  - 支持受管主机别名：`host add/rm/list`
  - 每个主机可单独设置认证模式：`key`、`password`、`auto`、`ask`
  - 可选密码策略：`stored`、`prompt`、`session`
- 交互式 Shell：
  - 直接运行 `secssh` 进入 `secssh>` 模式
  - 支持 TAB 补全
  - `Ctrl-C` 中断当前输入但不退出
  - `Ctrl-D` 退出 Shell

## 工作方式

`secssh` 并不自己实现 SSH，而是按下面的流程工作：

1. 解锁并解密保险库
2. 按需生成临时配置和密钥文件
3. 解析主机认证策略和运行参数
4. 调用系统 `ssh`
5. 清理临时产物

这样既能集中管理敏感信息，也能尽量保持与标准 OpenSSH 一致的运行方式。

## 环境要求

- Go `1.24+`
- OpenSSH 客户端工具（`ssh`）
- `ssh-keygen`，用于 `key gen` 等相关流程
- 推荐 Linux/macOS

## 构建

使用 Make 目标：

```bash
make build
make test
make build-one PLATFORM=linux/amd64 VERSION=v0.1.0
make build-cross VERSION=v0.1.0
```

输出位置：

- 本地构建：`bin/secssh-<version>`
- 跨平台构建：`dist/secssh-<version>-<os>-<arch>[.exe]`

## 快速开始

默认使用本地 vault，也可以通过 `--vault` 指定自定义 vault 来源。远程 `http(s)` vault 会先下载到本地缓存，并按只读方式使用。

```bash
secssh --vault https://example.com/vault.enc status
```

初始化或解锁保险库：

```bash
secssh unlock
```

添加一个受管主机：

```bash
secssh host add prod --hostname 10.0.0.10 --user root --port 22
```

生成密钥并复制到主机：

```bash
secssh key gen prod-key
secssh key copy prod-key prod
```

设置主机认证方式并连接：

```bash
secssh host auth set prod --mode key
secssh ssh prod
```

查看已保存的主机和历史：

```bash
secssh host list
```

## 命令概览

```text
secssh --vault <path-or-url> <command>

secssh unlock
secssh lock
secssh status

secssh ssh <target> -- [ssh args...]

secssh config set --file <path>
secssh config show

secssh key add <name> --file <private_key>
secssh key gen <name> [--type ed25519|rsa] [--bits 4096] [--comment <text>]
secssh key copy <name> <host-alias> [--auth ... --prompt --use-secret ...]
secssh key list
secssh key rm <name>

secssh secret add <name>
secssh secret rm <name>
secssh secret list

secssh host add <alias> --hostname <host> [--port 22] [--user <user>]
secssh host rm <alias>
secssh host list
secssh host auth set <alias> --mode <key|password|auto|ask> [...]

secssh passwd

secssh crypto show
secssh crypto set --kdf <name> --cipher <name>
```

## 安全说明

- secrets 和私钥会以静态加密形式存储在保险库中。
- 保险库写入采用原子方式，以降低文件损坏风险。
- 运行时密钥文件会以严格权限落盘，并在使用后清理。
- 敏感信息默认不应出现在日志中。
- 修改密码和加密算法时会触发完整保险库重加密。

## 项目文档

- 需求说明：`docs/requirements.md`
- 设计说明：`docs/design.md`

## 当前状态

项目核心工作流已经可用，并仍在持续演进中。
欢迎提交 Issue 和 Pull Request。
