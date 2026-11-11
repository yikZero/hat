# hat

> 给命令行程序“换一顶帽子”：每个 profile 有自己的出口 IP（只走代理、断了就断网）、语言、时区；vm 模式下还有独立的主机名、machine-id、MAC 地址和账号凭证。像指纹浏览器管理浏览器窗口一样，管理你的 CLI 环境。

适用场景：在不同地区/语言环境下测试程序、把工作与个人的账号和网络彻底分开、隐私保护。

```
teil chat                 # 通过 shim，自动在 us-east profile 里运行
hat run jp -- curl https://example.com
hat shell us-east
```

## 两种模式

| | `lite` | `vm`（默认） |
|---|---|---|
| 原理 | macOS 沙箱（Seatbelt）+ 本地桥接代理 | 每个 profile 一台 Linux 轻量虚拟机（vfkit） |
| 启动速度 | 立即 | 首次几分钟（安装系统），之后秒级 |
| 出口 IP / DNS 不泄露 / 断网保护 | ✅ 内核沙箱强制 | ✅ 虚拟机只有一条通往代理的网络路径 |
| 语言、时区 | ✅ | ✅ |
| 主机名、machine-id、MAC | ❌（与本机相同） | ✅ 每个 profile 独立 |
| 账号凭证 / Keychain | ❌ 共享（可选独立 HOME） | ✅ 完全独立 |
| 运行的程序 | 你 Mac 上装的版本 | VM 里装的 Linux 版本 |
| 用系统 TLS 的程序（Go/Swift 写的 CLI） | 需 `--allow-trustd`，或改用 vm | ✅ |

## 安全保证（以及不保证什么）

**保证**
- 每个 profile **必须**配置代理。代理不可达时连接直接失败，**永远不会回落直连**。
- 域名不在本地解析，原样交给代理（socks5h 语义）；本机 DNS（mDNSResponder）在沙箱里被禁止；VM 内所有 53 端口查询由 hat 本地应答（fake-ip）。
- UDP（QUIC 等）、ICMP、IPv6 一律丢弃；访问本机/局域网/云元数据地址（169.254.169.254）被拒绝。
- lite 沙箱里的程序读不到 `~/.hat`（其它 profile 的代理密码）、不能调用系统打开浏览器（`open` 会用真实网络）。
- 代码层面：只有 `internal/upstream` 能发起网络连接，由测试 `internal/policy` 强制。

**不保证 / 已知限制**
- Shim 是便利不是强制：用绝对路径运行程序、IDE 或 Dock 启动的程序不经过 shim。
- VM 能被识别为虚拟机（DMI 显示 Apple Virtualization）。vfkit 每次启动会生成新的 GenericMachineIdentifier（只有 root 可读）。
- vm 模式的共享目录只读（`--ro`）在虚拟机内实现，VM 内 root 可以绕过；只能共享目录，不能共享单个文件；修改共享目录需重启 VM（`hat stop <p>`）。
- 如果上游代理在本机（如本地 Clash，需 `--allow-local-upstream`），断网保护取决于该代理自身不直连（请用全局模式、固定节点）。
- `lite` + `--allow-trustd` 时，系统证书服务可能用真实 IP 查询证书吊销状态（OCSP/CRL）。

## 安装

依赖：Apple Silicon Mac、macOS 13+；vm 模式需要 [vfkit](https://github.com/crc-org/vfkit) ≥ 0.6.1：

```bash
brew install vfkit
```

从源码构建（需要 Go 1.26+）：

```bash
make build-mac
```

```bash
sudo install -m 755 dist/hat-darwin-arm64 /usr/local/bin/hat
```

把 shim 目录放在 PATH 最前面（写进 `~/.zshrc`）：

```bash
export PATH="$HOME/.hat/bin:$PATH"
```

## 快速开始

```bash
hat create us-east --proxy 'socks5://user:pass@203.0.113.10:1080' --tz America/New_York --share ~/code
```

```bash
hat check us-east
```

`check` 会验证：出口 IP 是代理的 IP、DNS/UDP 不泄露、私网不可达、断网保护生效，以及主机名/machine-id/MAC。

在 profile 里运行命令（vm 模式下当前目录必须在共享目录内）：

```bash
cd ~/code/project && hat run us-east -- curl -s https://ipinfo.io
```

进入 profile 的 shell：

```bash
hat shell us-east
```

### 包装一个 CLI（例：teil）

vm 模式下，先在 VM 里装 Linux 版的 teil（举例，按 teil 的安装方式来）：

```bash
hat run us-east --home -- bash -lc 'npm install -g teil'
```

创建 shim，以后直接输入 `teil` 就会在 us-east 里运行：

```bash
hat shim add teil --profile us-east
```

同一个工具绑定另一个 profile：

```bash
hat shim add teil --as teil@jp
```

临时切换 profile：

```bash
HAT_PROFILE=jp teil chat
```

## 命令一览

| 命令 | 说明 |
|---|---|
| `hat create <p> --proxy URL [--mode vm\|lite] [--tz] [--locale] [--hostname] [--share DIR]` | 创建 profile；URL 里的密码会被移出并单独保存（0600 文件，或 `--keychain`） |
| `hat list` / `show <p>` / `edit <p>` / `rm <p>` | 管理 profile（`edit` 保存前会校验） |
| `hat proxy-password <p> [--keychain\|--none]` | 修改代理密码 |
| `hat share add\|rm\|list <p> [dir] [--ro]` | 共享目录 |
| `hat run <p> [--home] -- cmd...` | 运行命令；退出码、信号、管道、终端尺寸原样透传 |
| `hat shell <p>` | 交互式 shell |
| `hat shim add <cmd> --profile <p> [--as name]` / `shim rm` / `shim list` | 命令替身 |
| `hat start\|stop\|status <p>` | VM 生命周期（空闲 30 分钟自动关机） |
| `hat check <p>` | 泄露与断网保护检测 |
| `hat doctor` | 检查 PATH、vfkit、sandbox-exec |
| `hat debug-bundle <p>` | 打包日志用于反馈（不含密码） |

## 文件位置

```
~/.hat/profiles/<p>/profile.toml   配置（可编辑，0600，不含密码）
~/.hat/profiles/<p>/state.json     生成的身份：machine-id、MAC（不要手改）
~/.hat/profiles/<p>/secret         代理密码（password = "file" 时）
~/.hat/profiles/<p>/disk.raw       VM 磁盘
~/.hat/profiles/<p>/daemon.log     VM 守护进程日志；console.log 为 VM 控制台
~/.hat/bin/                        shim
~/.hat/images/                     基础系统镜像（Debian 13 arm64，下载一次）
```

## 开发

```bash
make test
```

```bash
make e2e
```

`make e2e` 在 Linux 上用一个假的 vfkit（gVisor 模拟的“虚拟机”）跑完整的 VM 生命周期：首次启动、命令执行、并发、停止、重启、守护进程崩溃恢复。真实 macOS 上的验证用：

```bash
scripts/macos-smoke.sh 'socks5://user:pass@host:port'
```

设计与调研：`docs/PLAN.md`、`docs/research.md`。
