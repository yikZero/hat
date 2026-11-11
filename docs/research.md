# hat 调研报告：macOS 上的「CLI 指纹环境」

> 目标：每个 profile 都有独立的出口 IP、DNS、语言、时区、主机名、机器 ID、MAC 地址和账号凭证。所有流量**只走代理**，代理挂了就断网，不回落直连。CLI 照常使用。
> 调研日期：2026-11

---

## 1. 结论

1. **GitHub 上没有现成的完整实现**。已有项目分三类，每类只解决一部分问题：
   - **只隔离配置目录**：多账号切换工具（aiwitch、claude-multiprofile、claude-switch），只切换配置目录，不管网络。
   - **强制代理的沙箱**：Anthropic 的 sandbox-runtime、Gemini CLI、Goose，用 Seatbelt 加本地代理强制所有流量走代理，但不伪装身份。
   - **macOS 上的 Linux 微型虚拟机**：apple/container、Lima、vfkit、krunvm，能提供独立的主机名、机器 ID 和 MAC，但没有"只走代理"的网络模式。
2. **主机名和硬件信息只能用虚拟机隔离**。macOS 没有按进程隔离这些信息的机制；DYLD 注入对开了 hardened runtime 的程序无效。
3. **语言选 Go**：Code-Hex/vz、vfkit、Lima、gvisor-tap-vsock、tun2socks、sing-box 都是 Go 写的。
4. **建议分两档**：
   - `lite` 档：不开虚拟机，用 Seatbelt 强制走代理，加上语言和时区设置。秒开，但不隔离主机名和硬件信息。
   - `vm` 档（默认）：每个 profile 一个 Linux 微型虚拟机，网卡只接到 hat 自己的用户态网络栈，网络栈后面只有上游代理。主机名、机器 ID、MAC 全部独立，物理上不存在直连路径。
   - 以后可以再加 `macvm` 档（macOS 虚拟机）。

---

## 2. 为什么不能在 macOS 本机伪装主机名和硬件信息

| 方法 | 结论 | 依据 |
|---|---|---|
| 按进程的 UTS namespace | macOS 没有这个机制 | — |
| `DYLD_INSERT_LIBRARIES` 注入，拦截 gethostname 或 IOKit 调用 | ❌ 系统自带程序、开了 hardened runtime 签名的程序都会忽略这个变量。经过公证的 CLI 基本都开了 hardened runtime | [Apple 开发者论坛](https://developer.apple.com/forums/thread/703757) |
| 关闭 SIP | ❌ 等于关掉整个系统的安全保护 | 同上 |
| CLI 常用的机器标识 | macOS 上读 `IOPlatformUUID`，Linux 上读 `/etc/machine-id` | [node-machine-id](https://npmjs.com/package/node-machine-id) |

结论：要按 profile 隔离主机名和硬件信息，只能用虚拟机。

---

## 3. 「只走代理、断了就断网」的几种做法

| 做法 | 强度 | 覆盖整个进程树 | 需要 sudo 或签名 | 备注 |
|---|---|---|---|---|
| 只设置 `HTTP(S)_PROXY` | 弱 | — | 否 | 不读这些变量的程序会直连，**会泄露** |
| **Seatbelt（sandbox-exec）**：只允许连接本地代理端口 | 强，内核强制 | ✅ 子进程会继承限制 | 否 | Anthropic [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)、Gemini CLI、Goose、[safe-shell-sandbox](https://docs.rs/crate/safe-shell-sandbox/0.1.1/source/src/macos.rs) 都在用。不读代理变量的程序会**连接失败而不是泄露** |
| pf 防火墙按 UID 限制 | 强 | ✅ 按用户 | 需要 sudo | 每个 profile 要建一个系统用户，用起来麻烦 |
| Network Extension（App Proxy Provider） | 强，可以透明代理 | ✅ 可以按进程匹配 | 需要 Apple 开发者签名和公证，扩展要用 Swift 写 | 参考 [mitmproxy local capture](https://mitmproxy.org/posts/local-capture/macos/)、Proxifier |
| sing-box TUN 加 `process_path` 规则 | 中 | ❌ 按可执行文件路径匹配，不按进程树 | 需要 sudo | macOS 上 `auto_route` **不会劫持 DNS**，必须单独加 hijack-dns 规则（[sing-box FAQ](https://sing-box.sagernet.org/configuration/inbound/tun/)） |
| **虚拟机网卡只接 hat 的用户态网络栈** | **最强**，没有直连路径 | ✅ 整个虚拟机 | 不需要 sudo，只要给二进制签上虚拟化权限 | 本方案的 `vm` 档 |

Seatbelt 要注意的地方：
- `sandbox-exec` 被苹果标记为已弃用，但仍然可用，各大 AI CLI 都在用。
- Seatbelt 不认识域名，域名过滤只能放在代理里做。
- 如果规则写成"允许连接所有 localhost 端口"，程序可以通过本机其他服务中转出去。应该**只放行单个代理端口**，Goose 和 Gemini CLI 都是这样写的。

---

## 4. 虚拟机方案对比（macOS，Apple Silicon）

| 项目 | 语言 | 定位 | 主机名、ID、MAC | 网络能否只走代理 | 适合本项目吗 |
|---|---|---|---|---|---|
| [Code-Hex/vz](https://github.com/Code-Hex/vz) | Go（cgo） | Virtualization.framework 的 Go 绑定 | 全部可控 | 可以，用文件句柄网卡接到自己的网络栈 | ✅ **底层首选**。Lima 和 vfkit 都基于它 |
| [vfkit](https://github.com/crc-org/vfkit) | Go | 命令行虚拟机管理器，podman、crc、minikube 在用 | `mac=` 可以指定 MAC | `virtio-net,unixSocketPath=` 能接 gvproxy 或自己的网络栈 | ✅ 可以作为原型阶段的后端，或参考它的实现 |
| [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) | Go | 虚拟机用户态网络栈（用来替代 slirp 和 VPNKit） | — | ⚠️ **出站流量是直接连外网的，不支持上游代理**，需要改造 | 参考它的 DHCP、DNS 和虚拟交换机部分 |
| [tun2socks](https://github.com/xjasonlyu/tun2socks) | Go | gVisor 网络栈加各种代理拨号器（HTTP、SOCKS、SS、SSH） | — | ✅ 天然把所有流量转给代理 | ✅ 和 gvisor-tap-vsock 拼起来用 |
| [Lima](https://lima-vm.io/docs/config/network/user-v2/) | Go | 完整的 Linux 虚拟机管理器 | 主机名取实例名，每个实例有独立的 `vz-identifier` | ❌ `propagateProxyEnv` 只设置环境变量，不强制 | 太重，只参考 |
| [apple/container](https://github.com/apple/container) / [containerization](https://github.com/apple/containerization) | Swift | 每个容器一个虚拟机，启动不到 1 秒 | 能通过 `--network ...,mac=` 指定 MAC；文档里没有主机名参数 | ❌ 走 vmnet NAT，直接连外网 | 只能在 macOS 26 上用。**架构值得参考**（vminitd、vsock gRPC、精简内核） |
| [libkrun / krunvm](https://github.com/containers/libkrun) | Rust/C | 用 TSI 让虚拟机的 socket 由宿主机代为连接 | — | ⚠️ TSI 是宿主机直接替虚拟机连外网，要换成 passt 或 gvproxy 模式 | 不选 |
| [Tart](https://tart.run/faq/) | Swift | macOS/Linux 虚拟机 | ✅ `tart set --random-serial --random-mac` | 只有 softnet、NAT、桥接，没有代理模式 | 可以参考它做 `macvm` 档 |

### 能被识别出是虚拟机
- Linux 虚拟机：DMI 信息显示为 "Apple Virtualization Generic"（[openbenchmarking 实例](https://openbenchmarking.org/system/2404092-NE-RESULTTXT19/apple_virtualization)）。
- macOS 虚拟机：`hw.model` 是 `VirtualMac2,1`，改不了。
- 一般 CLI 不会检查这些，但要清楚，虚拟机方案的指纹不等于一台真机。

### macOS 虚拟机的限制
- **同一台 Mac 最多同时运行 2 个 macOS 虚拟机**，这是苹果许可协议的规定，系统内核会强制执行，超出会报 `VZErrorVirtualMachineLimitExceeded`（[Eclectic Light](https://eclecticlight.co/2023/09/14/current-limitations-on-macos-virtual-machines-running-on-apple-silicon-macs/)、[mjtsai](https://mjtsai.com/blog/2022/08/04/how-apple-limits-vms/)）。
- 序列号可以随机生成（[Tart #943](https://github.aipraa306.workers.dev/cirruslabs/tart/issues/943)、[khronokernel](https://khronokernel.com/macos/2023/08/18/AS-VM-SERIAL.html)）。
- 许可协议允许的用途：软件开发、测试、个人非商业使用。

---

## 5. 现有的多账号 CLI 工具（只隔离配置目录）

- [aiwitch](https://github.com/baedonguri/aiwitch)、[claude-multiprofile](https://github.com/jmdarre-v/claude-multiprofile)、claude-switch：靠 `CLAUDE_CONFIG_DIR`、`CODEX_HOME` 这类变量切换配置目录。
- **已知问题**：macOS 上很多 CLI 把 token 存进系统 Keychain，**换配置目录隔离不了 Keychain**（[相关讨论](https://claudeissues.com/issue/24963-feature-support-for-multiple-accounts-profiles)）。`gh` 的登录状态也是全局的。
- 这说明：如果要隔离账号，要么用虚拟机，要么用独立的系统用户，光改环境变量不够。

---

## 6. 推荐架构

```
                          ┌───────────────────── macOS 宿主机 ─────────────────────┐
 hat shell us-east ─────►│ hat（Go 单个二进制文件）                               │
                          │  ├─ 虚拟机管理：Code-Hex/vz                              │
                          │  │    ├─ Linux 内核 + initramfs（精简配置，目标启动 <1s）  │
                          │  │    ├─ virtio-fs：只挂载 [share] 白名单里的目录          │
                          │  │    ├─ vsock：和虚拟机里的 hat-agent 通信（终端、信号）  │
                          │  │    └─ virtio-net（文件句柄或 unixgram）──┐              │
                          │  └─ 用户态网络栈（gVisor netstack）◄────────┘              │
                          │       ├─ TCP  → 上游代理（SOCKS5/HTTP，以后加 sing-box）   │
                          │       ├─ DNS  → fake-ip，实际解析交给代理做                │
                          │       └─ 其他（ICMP、非 DNS 的 UDP、IPv6）→ 丢弃            │
                          └───────────────────────────────────────────────────────────┘
                                         代理挂了 = 所有连接失败（不会回落直连）
```

### 每个 profile 的身份信息
| 项目 | 实现方式 |
|---|---|
| 主机名 | 启动参数传给虚拟机里的 agent，由 agent 设置 |
| 机器 ID | 每个 profile 有自己的 `/etc/machine-id`，再加上 vz 的 GenericMachineIdentifier |
| MAC 地址 | 创建 profile 时随机生成并保存 |
| 时区、语言 | agent 设置 `TZ`、`LANG`、`LC_*`，以及 `/etc/localtime` |
| 用户名和 HOME | 虚拟机里单独的用户 |
| 凭证 | 存在虚拟机自己的磁盘上（每个 profile 一个磁盘镜像） |
| 文件访问 | virtio-fs 白名单，可以设置只读或读写 |

### `hat check` 检测项
- 出口 IP 和地理位置（通过代理查询 ipinfo 这类服务）
- DNS 泄露检测
- IP 所在地和时区、语言是否一致
- **断网测试**：故意断开上游代理，确认所有连接都失败
- 列出这个 profile 当前的主机名、机器 ID、MAC

---

## 7. 实施路线

| 阶段 | 内容 | 产出 |
|---|---|---|
| M1 | `lite` 档：Seatbelt 只放行本地代理端口，本地桥接代理负责上游认证，注入语言和时区，用 Seatbelt 规则限制可访问的目录 | 秒开，强制走代理，带断网保护 |
| M2 | `vm` 档：Code-Hex/vz 启动 Linux 虚拟机，gVisor 网络栈转发到代理，vsock agent，virtio-fs 共享目录，独立身份 | 完整的指纹隔离 |
| M3 | `hat check`、profile 导入导出、sing-box 协议支持 | 一致性检测，支持更多代理协议 |
| M4（可选） | `macvm` 档（同时最多 2 个）、Network Extension 透明代理 | 对外显示为 Mac |

### 工程上要注意的点
- Code-Hex/vz 需要 cgo，二进制要签上 `com.apple.security.virtualization` 权限，ad-hoc 签名就够用。
- 苹果芯片上 Linux 内核必须是**未压缩**的镜像，否则会卡住（vfkit 文档有说明）。
- 需要跑 x86 程序时可以挂载 Rosetta（`--device rosetta`）。
- 宿主机睡眠后虚拟机时钟会漂移，需要做时间同步（vfkit 用 `timesync`）。

---

## 参考来源
- Code-Hex/vz: https://github.com/Code-Hex/vz
- vfkit: https://github.com/crc-org/vfkit
- gvisor-tap-vsock: https://github.com/containers/gvisor-tap-vsock
- tun2socks: https://github.com/xjasonlyu/tun2socks
- apple/container: https://github.com/apple/container
- apple/containerization: https://github.com/apple/containerization
- libkrun: https://github.com/containers/libkrun
- Lima user-v2: https://lima-vm.io/docs/config/network/user-v2/
- Anthropic sandbox-runtime: https://github.com/anthropic-experimental/sandbox-runtime
- safe-shell-sandbox (Seatbelt proxy-only): https://docs.rs/crate/safe-shell-sandbox/0.1.1/source/src/macos.rs
- mitmproxy macOS local capture: https://mitmproxy.org/posts/local-capture/macos/
- sing-box TUN: https://sing-box.sagernet.org/configuration/inbound/tun/
- nsproxy (Linux): https://github.com/nlzy/nsproxy
- Tart FAQ: https://tart.run/faq/
- macOS VM limit: https://eclecticlight.co/2023/09/14/current-limitations-on-macos-virtual-machines-running-on-apple-silicon-macs/
- Apple Silicon VM serials: https://khronokernel.com/macos/2023/08/18/AS-VM-SERIAL.html
- DYLD / hardened runtime: https://developer.apple.com/forums/thread/703757
- node-machine-id: https://npmjs.com/package/node-machine-id
- Apple Virtualization DMI example: https://openbenchmarking.org/system/2404092-NE-RESULTTXT19/apple_virtualization
