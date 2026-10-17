## **主包小学学历职业是杀猪师傅，完全不懂代码，本项目纯VIBE，主要目的是杀猪自动化，主包没看过一个字代码，不保证安全好用。**

## **README文件由DeepSeek生成，他满嘴黑话主包也没办法，管也管不动骂也骂不好，请各位自己找DeepSeek读然后解释给你们听。**

# Remote ACP Bridge

把**远端**的 ACP agent（opencode / qwen / openclaw …）经一条**带认证的 WebSocket** 暴露成宿主本地的 stdio ACP agent。宿主（AionUi、Zed 等）以为自己在跟本机 agent 说话；实际那条命令是 `remote_acp_client.py`，它把 stdin/stdout 上的 ndjson 帧原样转发给远端的 `remote_acp_server.py`，由服务端拉起并驱动真正的 agent 子进程。

工作目录也是这么搬的：客户端把宿主给的项目文件夹**挂进自己的共享**，服务端把那个共享**挂到本机**（Linux）或**链接到本机**（Windows），于是远端 agent 读写的还是宿主那个项目。

```
宿主(AionUi) ──stdio ACP── remote_acp_client.py ══wss══ remote_acp_server.py ──stdio ACP── agent
                                                              │
                                                      挂载/链接：宿主的共享目录
```

## Requirements

* **Python 3.10+**（服务端与客户端都只用标准库 ＋ [`websockets`](https://pypi.org/project/websockets/)）。
* 服务端（Linux）：**RHEL 系**（RHEL / Rocky / AlmaLinux / Fedora），`install.sh` 用 `yum`/`dnf` 装 `python3-websockets`、`cifs-utils`、`nfs-utils`；Debian/Ubuntu 得自己装这几个包。另需 **systemd** 和一份内核支持的网络共享（SMB/NFS）。**只实测过 SMB（`cifs`）；NFS（`nfs4`）代码里支持，但没测过。**
* 客户端：Linux 或 Windows 都能跑，**不需要第三方包**。Windows 上要给宿主做目录链接时见 Troubleshooting。
* 网络：只要能 TCP 到服务端端口即可；**建议上 TLS**（`wss://`），因为桥 key 是明文头。

## Install（Linux 服务端）

```bash
sudo <交付根>/install.sh
sudo systemctl enable --now remote-acp-helper.service
sudo systemctl enable --now remote-acp-server@<instance>
```

`install.sh` 做的事：建 `agent` 服务账号 → `dnf` 装依赖 → 把 `systemd/` 里两个单元里的 `@ROOT@` **就地渲染**成交付根的绝对路径，再 `ln -sf` 到 `/usr/lib/systemd/system/` → `systemctl daemon-reload`。**幂等**：第二次跑时单元里已无 `@ROOT@`，`sed` 无变化、链接照旧。

两个单元：

* `remote-acp-server@<instance>.service` —— 模板实例，跑 `app/src/remote_acp_server.py --instance %i --instances-dir @ROOT@/configs`，以 `agent` 账号运行。
* `remote-acp-helper.service` —— **root** 常驻的挂载辅助，跑 `app/src/remote_acp_helper.py --config @ROOT@/configs/helper.toml`。桥自己无权限挂载，挂载动作全在这一侧。

> 整份交付被拷到别处时，单元里渲染好的旧绝对路径不会自动更新——重新跑一次 `install.sh` 即可。

## Windows

两端都能在 Windows 上跑，差别只在工作区怎么落地：Linux 用 helper 以 root 真挂载，**Windows 没有 helper**，改用**目录符号链接**把共享链接进来。

### 服务端跑在 Windows

* 没有 systemd，直接起进程：`python src\remote_acp_server.py --config <server.toml>`（交付包里入口在 `app\src\` 下，仓里就在 `src\` 下）。Windows 的服务端配置样例在交付包 `app\examples\server.windows.toml`。
* `[workspace].root` 必须是**带盘符的绝对路径**（如 `C:\ProgramData\remote-acp-bridge\workspace`）；写成 `/home/...` 这类 POSIX 路径会按配置错误退 `1`。
* 分支 A（客户端配了 `[servers.workspace]`）：服务端在 `<root>\<客户端 hostname>` 建一条**目录符号链接**指向客户端的 UNC 共享 `\\<host>\<share>`；会话 cwd 是 `<root>\<hostname>\<链接名>`。
* 分支 B（客户端没配）：`<root>\localhost\<宿主 cwd 的最后一段>`，只建普通目录。
* **建链接要特权**：`mklink /D` 需要 `SeCreateSymbolicLinkPrivilege` —— 要么以**管理员**起服务端，要么打开 Windows **开发者模式**（设置 → 系统 → 开发者选项）。没权限时报 `cannot create the share link: You do not have sufficient privilege to perform this operation.`。
* `mklink /J`（junction）**指不了 UNC**，所以只能用 `/D`。
* 不想让服务端带管理员身份也有办法：**管理员手工预建那条链接一次**，之后服务端用普通账号跑——链接已存在且指向同一个 UNC 时走复用分支，不再调 `mklink`。服务端拉起的 agent 继承服务端自己的令牌，所以服务端不是管理员，agent 也就不是。

### 客户端跑在 Windows

* 只需要 Python，不需要第三方包。
* `[servers.workspace]` 里填 `share_dir`（本机要暴露给远端的目录）、`device`（该共享的 UNC，如 `//fileserver.example.net/ws`）、`fs_type = "cifs"` 和账号口令。客户端会在 `share_dir` 里建目录符号链接指向宿主给的项目文件夹，服务端那边看到的就是这个共享。
* 宿主用 stdio 拉起客户端时，**启动器的 stdout 就是 ACP 通道**：`.bat` 首行必须是 `@echo off`，里面也不许往 stdout 打任何字，否则宿主会收到 `-32700 Parse error`。日志走 `[servers.logging]` 的文件。

## Configure

示例配置：服务端 `config.example.toml`、helper `helper.example.toml`、客户端 `client.example.toml`、密钥文件格式 `keys.example.txt`。

### 服务端 `server.toml`

配置路径：`--config <file>`，或 `--instances-dir <dir>` ＋ `--instance <name>` ＝ `<dir>/<name>/server.toml`；两者都给时 `--config` 优先。**两者都没给 ⇒ 退出码 2**。相对路径（证书等）按**该配置文件所在目录**解析。

| 表 | 键（默认值） |
| --- | --- |
| `[server]` | `host=""`（空＝双栈 v4+v6 同一端口；`"0.0.0.0"` 只 v4、`"::"` 只 v6）/ `port=7801`（必须 1–65535）/ `max_sessions=0`（0＝不限）/ `connection_idle_seconds=0`（0＝不判定）/ `session_grace_seconds=0`（0＝断开后一直保留） |
| `[server.tls]` | `enabled=false` / `cert_file=""` / `key_file=""`（`enabled=true` 时两者必填且文件必须存在） |
| `[auth]` | `mode="key"`（只支持它）/ `keys_file`（**必填**，文件必须存在）/ `clock_skew_seconds=300` / `nonce_cache_seconds=600` |
| `[logging]` | `level="off"`（`off`\|`debug`\|`info`\|`warn`\|`warning`\|`error`）/ `file=""`（留空写 stderr） |
| `[[agents]]` | `name` / `command` / `args=[]` / `cwd=""` / `env={}`（追加到父进程环境）/ `plugins=[]` |
| `[[agents.plugins]]` | `name`（内置插件名，必填）/ `config`（表，必填；插件拿到的就是它） |
| `[workspace]` | `root`（**必填、必须绝对路径**）/ `helper_socket="/run/remote-acp-helper.sock"` / `mount_uid="agent"` / `mount_gid="agent"` / `monitor_interval_seconds=5` / `monitor_timeout_seconds=2` / `monitor_fail_threshold=3` |
| `[env]` | 该实例**所有 agent 共用**的环境变量（键→字符串，可选）。合并阶梯（低→高）：`os.environ` → `[env]` → `[[agents]].env`（覆盖全局） → 桥注入的会话事实（见下）。 |

`[auth].keys_file` 是**服务端**的桥 key 文件：**一行一个 key**（不写用户名），`#` 起注释（整行或行尾），空行忽略，key 本身不能含 `#`；认证时逐个常量时间比对，命中任意一行即通过。客户端不读这个文件——它的 key 写在每个 `[[servers]].key` 里。

子进程环境里桥还会注入三个**会话级**变量（拉起 agent 那一刻定死，重连不变）：`REMOTE_ACP_BRIDGE_CLIENT`（分支 A 才有，客户端 hostname 原样）、`REMOTE_ACP_BRIDGE_IPVERSION`（`4`/`6`，按那条连接的传输层 socket family；判不出就不注入）、`REMOTE_ACP_BRIDGE_SID`（该会话的桥会话 uuid）。它们**压过**同名配置项，覆盖时打一行英文日志。

最小可用（Linux）：

```toml
[server]
port = 7801

[auth]
keys_file = "keys.txt"

[logging]
level = "info"
file  = "/var/log/rab/server.log"

[[agents]]
name    = "opencode"
command = "opencode"
args    = ["acp"]
cwd     = "/home/agent"

[workspace]
root = "/home/agent/workspace"
```

`[workspace].root` 是服务端本机的**挂载根**：每个客户端挂在自己的 `<root>/<客户端 hostname>` 下。宿主给的会话 cwd 走两条分支——客户端配了 `[servers.workspace]` ⇒ **分支 A**，用「挂载点 ＋ 链接名（项目文件夹名）」；没配 ⇒ **分支 B**，用宿主 cwd 的**最后一段**（ASCII 清洗成单段）当 `<root>/localhost/<最后一段>`，同名即同目录。

会话工作目录检查（把会话开启帧转给 agent 之前）会对分支 A 做三段检查：① 挂载点真的挂载；② 存在；③ 可读且是目录。任一失败都**不结束会话**，只把那条请求回一个 JSON-RPC error，`code=-32001`：

```
session working directory is not accessible in the mounted share: <原因>
```

客户端再把它翻成宿主看到的最终文案（本机路径以客户端为准、账号取 `[servers.workspace].username`）——没权限那条逐字为：

```
session working directory is not accessible in the mounted share: Permission denied; grant the share account '<账号>' read access to '<客户端那个文件夹>' on the client.
```

服务端**绝不 `mkdir`** 进共享（那是宿主的盘）；分支 B 与 `[[agents]].cwd` 是本机路径，该建就建。

### 客户端配置

```bash
remote_acp_client.py --config <client.toml> --server <name> --agent <name> [--session <uuid>] [--insecure] [--quiet]
```

`--config` / `--server` / `--agent` **必填**（缺了退 2）。`[[servers]]`/`[servers.*]` 逐项：

| 表 | 键（默认值）与后果 |
| --- | --- |
| `[[servers]]` | `name`（必填）/ `host`（必填；可写 IPv6 字面量 `::1`，URL 里会自动加方括号）/ `port=7801` / `key`（**必填**，该 server 自己的桥 key）/ `agents=[]`（客户端本机白名单；空＝不限，写了则名单外的 `--agent` 在**加载阶段**报错退 1） |
| `[servers.tls]` | `enabled=true` / `insecure=false` / `ca_file=""`（相对路径按 client.toml 所在目录解析）/ `fingerprint=""` |
| `[servers.workspace]` | `hostname`（**必填**，就是服务端认的客户端名）/ `share_dir`（本机对那个共享的挂载点）/ `fs_type="cifs"` / `device`（cifs 写 `//host/share`；nfs4 写 `host:/export`）/ `mount_options=[]` / `username` / `password` / `domain=""` / `sentinel_token`（**必填**） |
| `[servers.logging]` | `level="off"` / `file=""`（相对路径按 client.toml 解析；`debug` 时把帧 trace 也写进同一文件） |
| `pass_mcp`（`[[servers]]` 键） | `["*"]`。名单里出现 `*` 或整条不写 ⇒ 上行 `session/new\|load\|resume` 的 `params.mcpServers` 一字不改；给了不含 `*` 的名单 ⇒ 只留 `name` 命中的项（没有 `name` 的项一律删）；`pass_mcp = []` ＝ 全删。 |

`[servers.workspace]` 是可选的：不配 ⇒ 该 server 走**分支 B**（服务端忽略宿主 cwd）。配了 ⇒ 客户端启动时会在 `share_dir` 里：
* 把宿主 `session/new` 的 cwd 按**项目文件夹名**建目录链接（同名直接复用）；Linux 用 `symlink`，Windows 用 `mklink /D`（目录符号链接，见 Troubleshooting）；
* **自动补** `.rab-workspace-token`（内容＝该 server 的 `sentinel_token`；已存在则不动）。它是服务端的**哨兵**：挂载后服务端要读到这个文件且内容相等，才认为「挂的是对的那个共享」。

最小可用（Linux 客户端）：

```toml
[[servers]]
name   = "linux-host"
host   = "linux.example.net"
port   = 7801
key    = "k-your-bridge-key"
agents = ["opencode"]

[servers.tls]
enabled  = true
insecure = false
ca_file  = "/etc/rab/client.crt"

[[servers]]
name = "local-v6"
host = "::1"
port = 7801
key  = "k-local"
tls  = { enabled = false }
```

共享凭据：`username`/`password` 写在 `client.toml` 里（该文件请置 `0600`，这是它唯一的落点）。运行时它只在内存里进握手 `Config` 头 → 连接 → 服务端 → helper 的 Unix socket；helper 把它写成**临时 `0600` 凭据文件**交给 `mount -o credentials=…`，用完即删。**不进 argv、不进日志**。

### 插件（服务端）

`[[agents.plugins]]` 挂在哪条 `[[agents]]` 下，该 agent 的每一帧（两个方向）就按**书写顺序**过插件链。每项只有 `name` ＋ `config` 两个键；不写＝纯透传。内置两个：

* `aionui_remove_skill_prompt` —— 删掉 AionUi 塞在用户文字前、包在 `[Assistant Rules]…[/Assistant Rules]` 里的 `## Available Skills` 那一段。**每条 agent 都建议挂**。
* `aionui_openclaw_adapter` —— openclaw 的 ACP 面不广告模型清单与 permission mode：本插件替它补出模型下拉与 `mode` 下拉，并把选择翻成 openclaw 自己的 `/model` 命令与 `gateway call sessions.patch`。需要 `config.openclaw_command`（CLI 绝对路径，唯一门槛、无默认值）。**只给 openclaw 挂**。

插件抛错或超时 ⇒ 打一行英文日志、那一帧**原样放行**（fail-open），不弄断会话。

## Run

服务端：

```bash
python3 src/remote_acp_server.py --config configs/prod/server.toml
python3 src/remote_acp_server.py --instances-dir configs --instance prod
python3 src/remote_acp_helper.py --config configs/helper.toml    # root；--config 必填
```

客户端（宿主把这条配成一个 agent 命令）：

```bash
python3 src/remote_acp_client.py --config client.toml --server linux-host --agent opencode
```

交付包里的入口在 `app/src/` 下，仓里就在 `src/` 下，其余一致。

会话建立后客户端会往 stdout 注入**一条** ACP `session/update` 通知，正文是该会话的桥 uuid；同一 uuid 也打在 stderr（`connected ws://… session=<uuid> (new|resume)`）。**stdout 只有 ACP JSON 行**，其余一律 stderr。

### 握手与关闭码

握手一次 `GET /agents/<agent>` 升级，全部用 `X-Remote-ACP-Bridge-*` 头：

```
X-Remote-ACP-Bridge-AuthKey:    <桥 key>
X-Remote-ACP-Bridge-Timestamp:  <unix 秒>
X-Remote-ACP-Bridge-Nonce:      <随机串>
X-Remote-ACP-Bridge-Session-Id: <旧会话 uuid>     ← 只有续连带
X-Remote-ACP-Bridge-Config:     <base64(json)>   ← 总是带
```

`Config` 里（base64 之前）是 `{"workspace": {…}}`；**没配 workspace ⇒ `{}`**。认证失败回 `401` 并立即断开；workspace 挂载/闸门不过回 `HTTP 412` ＋ 一句英文理由。任一步失败都不建会话。

关闭码：客户端发 `1000` ＝ 会话结束；服务端发 `1000` ＝ 会话本身已结束（客户端**不再重连**）；`1001` ＝ 只是这条连接被丢弃（空闲超时/被新连接取代），客户端按退避用**同一个 uuid** 自动续连。

## Exit codes

客户端进程（`remote_acp_client.py`）：

| 码 | 含义 |
| --- | --- |
| `0` | 正常结束（含宿主自己关 stdin） |
| `1` | 配置错误（TOML 语法坏、字段非法、文件缺失、keys 非 UTF-8） |
| `2` | 用法错误（缺 `--config`/`--server`/`--agent`、`--session` 不是 uuid 等） |
| `3` | 会话已结束且不可能再续（握手 `404`/`410`，或服务端以 `1000` 宣告结束） |
| `4` | 认证被拒（`401`） |
| `5` | 会话属于别的 agent（`403`） |
| `6` | TLS 层致命（对端证书校验失败、本地 TLS 材料建不出上下文、**证书指纹 pin 不符**） |
| `7` | workspace refused（挂载/闸门失败回 `412`、`Config` 头坏回 `400`） |
| `130` | Ctrl-C |

`1001`、网络异常、`503` ⇒ 自动重试（退避 0.5s 起、上限 10s）。

服务端：配置错误退 `1`，用法错误退 `2`，端口/监听绑不上退 `1`；`remote-acp-helper --config` 缺参退 `2`。

## Troubleshooting

* **挂载/链接要权限**：Windows 上建**目录符号链接**（`mklink /D`）需要**开发者模式或管理员** shell；`mklink /J`（junction）**指不了 UNC**，所以桥只用 `/D`。管理员**预建一次**之后，普通身份可以一直复用那条链接。
* **helper 的 `--config` 是必填**：它是 root 常驻服务，路径全靠命令行给（没有默认配置路径）；缺参按用法错误退 `2`。
* **SMB 服务账号至少读权限**：要挂 SMB 共享，客户端 `[servers.workspace].username` 指定的那个服务账号，对下列文件夹**至少要有读权限**，否则服务端会明确回「没权限」而不是误报「不存在」：

  ```
  C:\Users\<用户>\AppData\Roaming\AionUi\aionui\conversations\users
  C:\Users\<用户>\AppData\Local\Temp
  未来需要挂载的目录
  ```

* **`/etc/systemd/system/<unit>` 会遮蔽 `/usr/lib`**：`install.sh` 把单元放进 `/usr/lib/systemd/system/`；如果 `/etc/systemd/system/` 下有同名单元，systemd 优先用后者。它不会自动删，请自己确认。
* **证书指纹 pin**：`[servers.tls].fingerprint` 填 `base64(SHA-256(对端证书 DER))`。配了它，**升级请求发出之前**就会校验对端证书，不符打 `tls certificate fingerprint mismatch` 退 `6`、不重连。**与 `insecure` 正交**：`insecure = true` 只关掉 CA/主机名校验，pin 照样必须过（自签证书就是这组合）。值必须是合法 base64 且解出正好 32 字节，否则加载即报错退 `1`。

## Source layout

```
src/remote_acp_{server,client,helper}.py   # 两个入口 shim ＋ helper
src/remote_acp_bridge/                     # 包：server / client / session / workspace / mounting / helper / config / auth / frames
  plugins/                                 # 内置服务端插件
  resources/                               # 插件用的提示词资源
systemd/                                   # 两个单元（@ROOT@ 占位）
install.sh                                 # Linux 安装（就地渲染 @ROOT@ 后 ln -sf 进 /usr/lib/systemd/system）
build.py build.bat run.bat devrun.py
config.example.toml client.example.toml helper.example.toml keys.example.txt
```

单元测试不随本仓发布；`build.py` 是开发树里的工具，要跑完整条链（含单测与构建产物目录）需要仓库之外的那几个目录。
