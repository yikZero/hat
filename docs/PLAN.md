# 最终方案 v2（经 3 路审核）

> 审核：① 安全/泄露 ② macOS VM 可行性 ③ 产品/架构/命名。本文是合并后的定稿。
> 调研背景见 `docs/research.md`。

## 0. 总原则
1. **Fail closed**：任何一环出问题（profile 解析、代理、daemon、sandbox-exec、vfkit）都报错退出，**绝不**回落为直接运行真实程序或直连网络。
2. **唯一的出网代码** 在 `internal/upstream`，且只连代理服务器本身。CI 用 lint 禁止其他包出现 `net.Dial*` / `net.Lookup*` / `net.Resolver`。
3. 主程序纯 Go（`CGO_ENABLED=0`），在 Linux 上交叉编译 darwin/arm64。

## 1. lite 档（不起 VM）
- 进程内起**桥接代理**（127.0.0.1 随机端口，HTTP+SOCKS5 同端口，**每次运行随机凭证**），只经 upstream 转发；拒绝 loopback/私网/链路本地/CGNAT/ULA/组播/`localhost`/`*.local` 目标；拒绝 UDP ASSOCIATE/BIND。
- `sandbox-exec` 使用 **`(deny default)` 白名单**策略（以 Anthropic sandbox-runtime 的 macOS 规则为蓝本），网络只放行 `(remote tcp "localhost:<port>")`；显式拒绝：
  - mDNSResponder unix socket、`com.apple.dnssd.service` 等 mach 服务（防 DNS 泄露）
  - `nsurlsessiond`、`lsopen`、`appleevent-send`（防系统代发请求/打开宿主浏览器）
  - `~/.hat` 下除本 profile home 以外的读写（防偷其它 profile 的代理密码）
  - unix socket 默认全拒（docker.sock 等永不放行）
- **trustd（系统证书校验）**：默认拒绝（因为 trustd 会用真实 IP 去查 OCSP/CRL）。代价：用系统 TLS 的程序（Go/Swift 写的 CLI，如 gh、terraform）在 lite 档会 TLS 失败 → 用 `allow_trustd = true` 显式放开（会提示风险），或改用 vm 档。Node/Python/curl(OpenSSL) 不受影响。
- 注入：`HTTP(S)_PROXY`/`ALL_PROXY=socks5h://...`（大小写两套）、`NO_PROXY=`、`LANG/LC_ALL/TZ`、`BROWSER=<打印 URL 的 helper>`、`JAVA_TOOL_OPTIONS=-Djava.net.preferIPv4Stack=true`、`HAT_ACTIVE=<profile>`；可选隔离 HOME。
- 前台运行：转发信号、透传退出码（信号 → 128+n），不需要 daemon。

## 2. vm 档
### 2.1 vfkit（≥ 0.6.1，启动时检查版本）
```
vfkit --cpus N --memory MB --pidfile <run>/vfkit.pid
  --bootloader efi,variable-store=<p>/efi-vars,create
  --device virtio-blk,path=<p>/disk.raw
  --device virtio-net,unixSocketPath=<run>/net.sock,mac=<MAC>     # 唯一网卡，启动前断言
  --device virtio-rng
  --device virtio-serial,logFilePath=<p>/console.log
  --device virtio-fs,sharedDir=<dir>,mountTag=s0 ...               # 白名单目录
  --cloud-init <p>/seed/user-data,<p>/seed/meta-data
```
- 不开 `--restful-uri`、`--ignition`、`nat`；关机：guest `poweroff` → SIGTERM → SIGKILL。
- 启动前删除残留 socket；所有 socket 放 `~/.hat/run/<8位hash>/`（0700，避开 104 字节限制）。

### 2.2 网络栈（`internal/netstack`）
- 复用 gvisor-tap-vsock 的 `pkg/tap`（交换机 + vfkit unixgram 握手）、`pkg/transport`、`pkg/services/dhcp`；**不用** `virtualnetwork.New()`（其 TCP/UDP/ICMP 转发、DNS、NAT 全是直连）。
- 自写：
  - **TCP**：gVisor `tcp.NewForwarder` → 先经 upstream 拨号，成功再 `CreateEndpoint`，失败 `Complete(true)` 发 RST（= kill switch）。
  - **DNS**：拦截所有 53 端口（不论目的 IP）；A → fake-ip（198.18.0.0/15）；AAAA → 空；其它类型 → NXDOMAIN/空（v1 不做 DoH）。
  - 目的地是未映射的 fake-ip、网关、私网、169.254.169.254 → RST。
  - UDP（除 DNS）/ICMP/IPv6：丢弃。
  - 计数器：非 upstream 出网次数（恒为 0，供 check 断言）。
- 宿主机访问 guest sshd：daemon 通过自己的网络栈 `gonet.DialContextTCP(guestIP:22)`，**不开宿主端口**。

### 2.3 镜像与身份
- Debian 13 `genericcloud-arm64` tar.xz（~214MB），纯 Go 解压为稀疏 raw → `~/.hat/images/`；每个 profile `clonefile` 复制 + 扩容。
- cloud-init（NoCloud）：hostname、时区、locale、用户（**uid 501 / gid 20**，与宿主一致，NOPASSWD sudo，profile 专属 SSH 公钥）、写 `/etc/machine-id`、挂载共享目录到**同一绝对路径**、关闭 apt-daily/unattended-upgrades/motd-news/timesyncd/IPv6、首启结束后重启一次（让 machine-id 生效）。
- 时间：每次 `run` 通过 ssh `sudo date -s @<epoch>` 校准（不依赖 NTP / qemu-ga）。
- 已知限制（文档写明）：vfkit 每次启动随机 GenericMachineIdentifier（只有 root 能读 DMI）；DMI 显示 Apple Virtualization；共享目录只读只能在 guest 内软实现；不能共享单文件（启动时复制进去）；改共享目录需重启 VM。

### 2.4 daemon 与并发
- `hat daemon <p>`（隐藏命令）托管 vfkit + 网络栈；`flock(daemon.lock)` 判活；首个客户端拿 start 锁启动，其余等待 ready；启动时清理孤儿 vfkit（pidfile）；会话计数 + 空闲自动关机。
- 控制 API：unix socket 上 JSON，带 `proto_version` 握手；`ssh` 通道：客户端连 `<run>/ssh.sock`，daemon 转发到 guest:22。

### 2.5 会话
- 宿主内置 `x/crypto/ssh` 客户端；stdin+stdout 都是 TTY 才申请 PTY（透传 TERM、窗口大小变化）；否则管道模式（stderr 分离、EOF 传播）；信号转发；exit-signal → 128+n；拒绝 guest 发起的任何 channel（agent/X11/端口转发）。
- env 白名单透传：TERM、COLORTERM、NO_COLOR、COLUMNS、LINES + `[env]`；**永不**透传宿主代理变量和 SSH_AUTH_SOCK。
- cwd 不在共享目录内 → 明确报错并提示 `hat share add`。

## 3. Shim（Volta 式）
- `~/.hat/bin/<name>` 是指向 hat 二进制的**符号链接**，按 argv[0] 分发；映射存 `~/.hat/shims.toml`（命令名、profile、lite 档下真实程序的稳定路径如 `/opt/homebrew/bin/teil`）。
- `hat shim add teil --profile us-east [--as teil@jp]`。
- profile 解析：`HAT_PROFILE` > shim 绑定的 profile。
- 嵌套保护：`HAT_ACTIVE` 与目标同 profile → 直接 exec 真实程序；不同 profile → 报错。
- 文档：shim 是便利不是强制（IDE/绝对路径会绕过）；`hat doctor` 检查 PATH 顺序。
- v1 不做目录 `.hat` 文件（防止 clone 下来的仓库自动切换 profile）。

## 4. 配置
`~/.hat/profiles/<p>/profile.toml`（0600，目录 0700，权限过宽拒绝加载）
```toml
schema = 1
mode = "vm"                 # vm | lite
locale = "en_US.UTF-8"
timezone = "America/New_York"

[proxy]
url = "socks5://user@host:1080"   # 不含密码
password = "keychain"              # keychain | file | none

[env]
FOO = "bar"

[[share]]
path = "~/code"

[lite]
isolate_home = true
allow_trustd = false

[vm]
cpus = 2
memory_mb = 2048
disk_gb = 16
hostname = "dev-box-07"
username = "dev"
idle_stop_minutes = 30
```
- 生成的身份（machine-id、MAC、SSH 密钥）存 `state.json` / `ssh/`，`edit` 不会改动。
- 密码：`keychain` 用 `security` CLI（交互输入，不上命令行）；`file` 存 `secret`（0600）。日志/输出一律脱敏。
- 上游代理在 127.0.0.1（如本机 Clash）需显式 `allow_local_upstream = true`，并警告“kill switch 依赖该代理自身不直连”。

## 5. 命令（v1）
```
hat create <p> --proxy URL [--mode vm|lite] [--tz] [--locale] [--hostname] [--username]
hat list | show <p> | edit <p> | rm <p>
hat shell <p>
hat run <p> -- cmd args...
hat shim add <cmd> --profile <p> [--as name] | shim rm <name> | shim list
hat share add|rm <p> <dir>
hat start | stop | status <p>
hat check <p>            # 出口 IP + kill switch + 泄露探针
hat doctor               # PATH、vfkit 版本、sandbox-exec
hat debug-bundle <p>     # 打包日志/版本/SBPL 方便反馈
```
砍掉（v1 不做）：地理/时区一致性启发式、目录 `.hat`、Rosetta、`bypass`、sing-box、DoH、UDP 代理。

## 6. 测试
- Linux：upstream/bridge（假代理、代理挂掉 → 失败）、SBPL 黄金文件、shim 分发、netstack（gVisor channel endpoint 注入包：DHCP、fake-ip DNS、TCP→代理、UDP/ICMP/私网被丢）、ssh 会话（Linux 上用 TCP 代替）、cloud-init 生成、vfkit 参数构建、lint 禁止直连。
- 交叉编译：darwin/arm64 主程序。
- Mac（用户）：`scripts/macos-smoke.sh` 逐项 PASS/FAIL + 结束时生成 debug bundle。
- GitHub Actions macOS runner 不支持嵌套虚拟化 → vm 档只能本机测；lite 档可在 `macos-15` runner 上测。
