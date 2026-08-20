# Windows 安装

[English](installation.windows.md) | [文档索引](../README.zh-CN.md#文档导航)

本文只覆盖 Windows Connector。Linux 与 macOS 请看
[installation.zh-CN.md](installation.zh-CN.md)；那两个才是受支持的发布目标，Windows 不是。

## 支持状态

Windows 不在 `connector/release/release-config.json` 的发布目标矩阵内。
`connector/packaging/windows/build-windows-package.ps1` 产出的压缩包
**不是可复现的发布产物**，它不具备 Linux 与 macOS 包所带的任何证据：

- 没有 Sigstore 签名，没有 OIDC 工作流身份；
- 没有 SLSA 来源证明，没有 SPDX SBOM；
- 没有可复现构建输入，没有 `SOURCE_DATE_EPOCH` 归一化；
- 没有受保护标签的发布工作流，没有不可变 GitHub Release。

请在将要运行它的主机上，从你自己信任的源码修订版自行构建。不要接收他人提供的该压缩包，
也不要再分发它。适用的发布边界见
[connector/release/README.md](../connector/release/README.md)。

## 前置条件

- Windows 10 1809 或 Windows 11，`amd64` 或 `arm64`。
- Windows PowerShell 5.1 或 PowerShell 7。默认安装路径不需要管理员权限。
- `ScheduledTasks` 模块，系统默认自带。
- **`codex-cli` 必须正好是 `0.147.0`。** Connector 在每次启动 app-server 前都会用
  `--version` 运行所配置的二进制，并要求横幅精确等于 `codex-cli 0.147.0`；固定的
  app-server schema 摘要也绑定到该版本。用 `codex --version` 确认，不一致就先升级：

  ```powershell
  npm install -g @openai/codex@0.147.0
  ```

  升级 Codex 是前置条件。Connector 不会绕过版本不匹配。
- 状态目录需要一个 NTFS 卷，详见下一节。
- 只有自行构建安装包时才需要 Go 1.24 或更高版本。

Connector 从不安装或升级 Codex，从不写入 `CODEX_HOME`，也从不开放入站监听端口。

## 状态目录可以放在哪里

Connector 在 `state_dir` 下保存 Ed25519 设备身份、已配对的设备凭据、配对状态、命令日志
和指标文本文件。在 Linux 与 macOS 上，这些由属主专属的 `0700` / `0600` 权限位保护。
在 Windows 上同样的保证由 ACL 表达，而两个实测的主机事实限制了目录位置。

### 必须位于 NTFS 卷

安装脚本调用 `GetVolumeInformationW`，并拒绝任何标志位缺少
`FILE_PERSISTENT_ACLS (0x8)` 的卷：

| 卷 | 文件系统 | 标志 | `FILE_PERSISTENT_ACLS` |
| --- | --- | --- | --- |
| `C:\` | NTFS | `0x3E72EFF` | 是 |
| `D:\` | NTFS | `0x3E72EFF` | 是 |
| `E:\` | exFAT | `0x20206` | 否 |

exFAT 与 FAT32 不记录属主也不记录 ACL，属主专属保证在其上无法强制执行。这里是硬性错误，
而不是降级为“跳过检查”——面对无法回答的 ACL 问题，Connector 一律失败关闭，与它在
Linux 和 macOS 上遇到不受支持的 ACL 查询时的行为一致。

### 不能放在 `C:\Users` 下

本机用户配置文件目录带有以下条目：

```text
C:\Users\peter heosdee\CodexSandboxUsers:(OI)(CI)(M,DC)
               S-1-5-21-984626594-3510769894-950914987-1305431254:(OI)(CI)(M,DC)
               NT AUTHORITY\SYSTEM:(OI)(CI)(F)
               BUILTIN\Administrators:(OI)(CI)(F)
               HEOSDEE\peter:(OI)(CI)(F)
```

`CodexSandboxUsers` 和第二个非本地 SID 都在配置文件目录上持有 `DC`
（`FILE_DELETE_CHILD`）。这两个组中的任何主体都能删除并替换 `C:\Users\peter` 的任意直接
子项，包括放在那里的状态目录。Connector 的祖先目录校验会在启动时拒绝它，报
`connector: state_dir or a directory above it is reachable by another principal`。
它**不会**点名是哪一级：终端错误的细节一律被抑制，因为错误信息可能携带工作区路径、
token 或配对码。要知道是哪一级，运行 `install.ps1`（它会点名），或用
`sub2api-codex-connector-ctl.ps1 pair` 在控制台里启动。目录上的 `DC` 正是 POSIX 中
“父目录对组可写且没有 sticky 位”的等价物，上游同样拒绝该情形。

安装脚本在创建任何内容之前就拒绝 `C:\Users`。**本机上不要把 `state_dir` 移到
`%LOCALAPPDATA%` 或 `%USERPROFILE%` 下。**

### 为什么 `D:\` 可用

```text
D:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
```

在 `D:\` 自身上，`Authenticated Users` 只持有 `(AD)`（`FILE_ADD_SUBDIRECTORY`）。
它能在卷根下新建条目，但不能删除或改名已有条目，因为它在 `D:\` 上没有
`FILE_DELETE_CHILD`，在子项上也没有 `DELETE`。因此 `D:\` 是可信祖先。

另外两条是可继承的，所以在 `D:\` 下按默认继承创建的任何对象都会对每个本地用户可读、
对每个已认证用户可写。因此安装脚本会切断 `D:\sub2api-codex-connector` 及其 `state`
子目录上的继承，并只授予三个受信主体：

```powershell
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
icacls <path> /inheritance:r `
  /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

这里的受托者用的是 SID 而不是名称：`SYSTEM` 和 `Administrators` 在本地化的 Windows 上
会被翻译，按名称写会解析失败。

它会**先**加固安装根目录，**再**在其中创建 `state`，这样状态目录从不会哪怕短暂地带着卷根
可继承的 `Authenticated Users` 授权存在。随后它重新读取生成的安全描述符，并在下列任一情况
下失败：DACL 未受保护、属主不是执行安装的用户、仍残留任何继承规则、或出现上述三者之外的
任何受信主体。

## 构建安装包

```powershell
cd <repo>\connector\packaging\windows
.\build-windows-package.ps1 -OutputDir C:\temp\connector-dist
```

该命令交叉编译 `windows/amd64` 与 `windows/arm64`，暂存三个运维脚本、配置模板、许可证文件、
一个 `SHA256SUMS` 文件和一个 `RELEASE-NOT-FOR-DISTRIBUTION` 标记文件，然后写出 zip。
命令会打印 zip 自身的 SHA-256，并重复“非发布产物”的警告。

如果固定版本的 Go 工具链不在 `PATH` 上，用 `-GoExe` 指定。

把 zip 解压到你自己掌控的位置，并从那里运行脚本。

## 安装

```powershell
.\install.ps1 `
  -WorkspaceRoot D:\code `
  -InstallRoot D:\sub2api-codex-connector `
  -Origin https://sub2api.wyswd.top `
  -DisplayName "My workstation"
```

安装脚本会：

1. 校验来源 origin、工作区根目录、状态卷以及状态路径形态（拒绝 `state:hidden` 这类 NTFS
   备用数据流，以及任何通配符）；
2. 创建并加固 `D:\sub2api-codex-connector` 与 `D:\sub2api-codex-connector\state`，随后
   校验结果；
3. 把 `sub2api-codex-connector.exe` 复制到 `D:\sub2api-codex-connector\bin`；
4. 通过解析 `npm prefix -g` 定位随包附带的 `codex.exe`，并核对其 `--version` 横幅；
5. 若 `D:\sub2api-codex-connector\connector.json` 尚不存在，则依据模板写入；
6. 注册名为 `sub2api-codex-connector` 的计划任务，在登录时以当前用户身份运行。

重复运行安装脚本会收敛：重新施加并重新校验 DACL、就地覆盖计划任务而不是重复注册，并且
**绝不覆盖已存在的 `connector.json`**。

常用开关：

| 开关 | 作用 |
| --- | --- |
| `-StateDir DIR` | 把状态目录放到 `INSTALLROOT\state` 以外的位置 |
| `-CodexBinary PATH` | 跳过 npm 解析，直接使用该 `codex.exe` |
| `-ConnectorBinary PATH` | 安装来自安装包之外的 Connector 可执行文件 |
| `-SkipTask` | 做完其余全部工作，但不注册计划任务 |
| `-AllowCodexVersionMismatch` | 在升级 Codex 之前先完成安装；Connector 仍会拒绝启动 app-server |

### 计划任务

任务在登录时以交互用户身份运行，使用 `-LogonType Interactive`，因此**不存储任何密码**。
它最多按 1 分钟间隔重启 3 次，没有执行时长上限，并使用 `IgnoreNew` 多实例策略，
避免第二个 Connector 与第一个争抢 `state_dir` 锁。

以真实交互账户运行是有意为之：Connector 需要该用户的 `CODEX_HOME` 凭据，而当属主是真实的
已登录账户时，属主专属的 ACL 模型也最自然。

### `codex_binary` 必须是 `codex.exe`

npm 安装会提供 `codex` 和 `codex.cmd` 两个 shim，但真正的可执行文件是：

```text
C:\Users\<you>\AppData\Roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe
```

安装脚本通过 `npm prefix -g` 解析该路径，而不是硬编码用户名；在 ARM 主机上会选择 `arm64`
的 vendor 目录。`.cmd` 或 `.bat` shim 会被拒绝：它会启动 `cmd.exe`，破坏 `--version`
检查的进程身份，在 Connector 与 Codex 之间插入一层批处理参数解析，并让真正的 Codex 进程
比 Job Object 所基于的句柄又远了一代。

## 配对

先配对再启动任务。配对需要 `state_dir` 锁，所以此时 Connector 不能已在运行。

```powershell
.\sub2api-codex-connector-ctl.ps1 pair
```

该命令以 `-pair-only` 运行 Connector，等待 `state_dir` 内出现私有的
`pairing-code.json`，然后打印配对码及其过期时间。打开已认证的 Control PWA，
选择 **Pair existing Connector** 并输入该码。保持命令运行，直到它确认浏览器端认领并退出。

**在配对码过期或被认领之前，把它当作敏感信息。** 只能在已认证的同源 PWA 中输入。
Connector 本身从不把配对码写入日志，只写 `pairing-code.json` 的路径；因此请限制对状态目录
以及任何记录了该码的控制台记录的访问。

如果 `pair` 提示 Connector 已在运行，先停止它：

```powershell
.\sub2api-codex-connector-ctl.ps1 stop
```

## 启动与验证

```powershell
.\sub2api-codex-connector-ctl.ps1 start
.\sub2api-codex-connector-ctl.ps1 status
```

`status` 打印三项互相独立的事实，任一不健康即以非零码退出：

```text
task:    \sub2api-codex-connector Running, last run 2026-08-20 11:04:12, last result 0x0
process: D:\sub2api-codex-connector\bin\sub2api-codex-connector.exe pid 24188
metrics: D:\sub2api-codex-connector\state\connector.prom last update 7s ago
config:  D:\sub2api-codex-connector\connector.json
state:   D:\sub2api-codex-connector\state
```

真正的健康信号是指标新鲜度，而不是 `codex_control_connector_up`。该 gauge 只有在**优雅**
停止后才会读到 `0`；进程被硬杀时，最后一次原子写入的文本文件会原样留下 `up 1`。
因此 `status` 要求 `codex_control_connector_last_update_timestamp_seconds` 与当前时间相差
不超过 60 秒，并把过旧和明显处于未来的值都视为不健康——这与 Linux、macOS 附带的外部
Prometheus 规则一致。

在 Windows 上该文本文件由 `windows_exporter --collector.textfile` 采集。采集器必须以
Connector 自己的账户运行，或以明确受信的特权服务运行；受保护的 DACL 意味着其他非特权账户
无法读取它。

## 工作区根目录在 PWA 中的显示形式

Control API 拒绝一切非绝对 POSIX 路径，而本部署中服务端不可修改。因此 Windows 路径从不
离开本机：Connector 在网络边界上用 Git-Bash 形式投影它们。

```text
D:\code\app        ->  /d/code/app
C:\Users\me\proj   ->  /c/Users/me/proj
\\nas\share\proj   ->  /unc/nas/share/proj
```

所以配置为 `D:\code\app` 的工作区根目录在 PWA 中显示为 `/d/code/app`，而 PWA 中每一个
`cwd`、审批 `path` 和授权根目录都使用同样的投影形式。**这不是 bug。** 在 `connector.json`
中就用普通的本地 Windows 路径配置 `workspace_roots`；投影在出站方向发生，并在入站方向被
反向还原。

阅读投影路径时需要注意：

- 投影形式中的盘符为小写。本地路径保留文件系统报告的规范大小写。
- `\` 变成 `/`。投影形式始终已经是规范化的；任何不能原样往返还原的路径都会被拒绝。
- UNC 路径 `\\host\share\...` 变成 `/unc/host/share/...`。
- 单独的卷根不能作为工作区根目录：`/c` 和 `/unc/host` 会被拒绝，这与既有的
  “文件系统根目录不能作为工作区根目录”规则一致。
- 值为 `.`、`..`、空串、以空格或点结尾，或为保留 DOS 设备名（`CON`、`PRN`、`AUX`、`NUL`、
  `COM1`–`COM9`、`LPT1`–`LPT9`）的路径分量会被拒绝，因为它们并不指向真实目录。
- 在 Windows 上，入站路径与已配置根目录的匹配不区分大小写。

## 日志

在计划任务下没有可读的控制台，因此 Connector 还会把 stderr 写入状态目录内的滚动日志文件，
该文件与其他状态对象使用同样的受保护 DACL 创建：

```text
D:\sub2api-codex-connector\state\connector.log
```

```powershell
.\sub2api-codex-connector-ctl.ps1 logs
.\sub2api-codex-connector-ctl.ps1 logs -Tail 500
.\sub2api-codex-connector-ctl.ps1 logs -Follow
```

如果日志不在 `state\connector.log`，用 `-LogPath` 指定。

配对码从不写入日志，只写 `pairing-code.json` 的路径。

## 升级

升级保留 `connector.json` 和整个状态目录，设备保持已配对状态。

```powershell
.\sub2api-codex-connector-ctl.ps1 stop
# 解压新的安装包，然后在新的安装包目录中执行：
.\install.ps1 -WorkspaceRoot D:\code -InstallRoot D:\sub2api-codex-connector
.\sub2api-codex-connector-ctl.ps1 start
.\sub2api-codex-connector-ctl.ps1 status
```

安装脚本会替换可执行文件和计划任务，并保持已有配置不变。

升级 Codex 时，先停止 Connector，再运行 `npm install -g @openai/codex@<version>`。
重新运行 `install.ps1` **不会**更新 `connector.json`：它绝不覆盖已存在的配置，而且它校验的是
自己刚解析出的二进制，不是配置里已记录的 `codex_binary`。如果升级后 vendor 目录下的
`codex.exe` 换了位置，需要你自己改 `codex_binary`。Codex 升级到偏离固定的 `0.147.0` 时，
Connector 会在启动 app-server 之前失败关闭。

## 卸载

```powershell
.\uninstall.ps1
```

这会移除计划任务并停止进程，但**保留 `state_dir`**，因为该目录存有已配对的设备凭据，
静默删除会强制重新配对。

若要同时删除状态，请先在 Control PWA 中吊销该设备，然后执行：

```powershell
.\uninstall.ps1 -PurgeState
```

`-PurgeState` 会在删除任何内容前要求输入 `purge` 一词确认。在自动化场景中可加 `-Force`
跳过确认。Codex 配置、Codex 凭据和工作区文件从不会被触碰。

## 故障排查

**`does not report FILE_PERSISTENT_ACLS`** —— 所选卷是 exFAT 或 FAT32。改用 NTFS 卷。
源码树位于 exFAT 卷没有问题；受约束的只有 `state_dir` 和安装根目录。

**`refusing to install under C:\Users`** —— 见
[不能放在 `C:\Users` 下](#不能放在-cusers-下)。改用 `D:\sub2api-codex-connector`。

**`grants access to S-1-5-…; only the Connector user, SYSTEM, and Administrators are
allowed`** —— 目录此前已存在，并带有另一个受信主体的显式 ACE。`icacls /grant:r` 只替换它
所指定主体的权限，会原样保留其他所有显式 ACE，所以安装脚本不能假定自己删除了它。
请查清该主体为何被授予访问权，用错误信息中打印的 `icacls … /remove:g` 命令移除它，然后
重新运行安装脚本。这里刻意设计为硬失败：意外的 ACE 是错误，绝不能跳过。

**`is owned by … not by the Connector user`** —— 该目录由另一个账户创建，或由提权 shell 在
“管理员创建的对象归 Administrators 所有”策略下创建。请以 Connector 用户取得所有权，
或删除该空目录让安装脚本自行创建。

**`codex reports 'codex-cli 0.145.0' but the Connector pins 'codex-cli 0.147.0'`** ——
运行 `npm install -g @openai/codex@0.147.0`。没有别的办法。

**`connector: state directory is already in use`** —— 另一个 Connector 进程持有
`state_dir` 锁。运行 `sub2api-codex-connector-ctl.ps1 stop`，用 `status` 确认没有残留进程，
然后重试。计划任务正在运行时执行 `pair` 失败，通常就是这个原因。

**`connector: state_dir is on a volume that cannot record access control
lists; choose an NTFS volume`** —— 与安装脚本拒绝的是同一种情况，之所以在运行时才出现，
是因为 `connector.json` 在安装之后被手工改过。参见
[必须位于 NTFS 卷](#必须位于-ntfs-卷)。

**`connector: state_dir or a directory above it is reachable by another
principal; choose a private location`** —— `state_dir` 路径上的某一级目录，把"替换其下内容"
的权限授予了外部主体。在装有 Codex 的机器上，这几乎总是因为 `state_dir` 位于 `C:\Users`
之下；参见[不能放在 `C:\Users` 下](#不能放在-cusers-下)。

其余所有失败都只打印 `connector: terminated with an error (details suppressed)`。这是有意为之：
错误信息可能携带工作区路径、bearer token 或配对码，而在计划任务下它会落进日志文件。上面两条之所以
例外，是因为它们是固定字符串，只描述"位置放错了"，不描述你的机器。想看底层错误，请停止任务并用
`sub2api-codex-connector-ctl.ps1 pair` 在控制台中运行 Connector，它会直接报告失败原因。

**登录时弹出控制台窗口** —— 任务以交互方式运行，Connector 的控制台附着在你的会话上。
这无害；相同输出也在 `state\connector.log` 中。可以最小化它，或在不希望它出现时停止任务、
改为手动启动 Connector。

**任务状态是 `Ready` 但没有进程在跑** —— 进程已退出。查看 `state\connector.log`，并在
`status` 中查看任务的上次结果。任务会按 1 分钟间隔最多重启 3 次后放弃；`start` 可重新运行它。

**`status` 显示进程在运行但指标过旧** —— Connector 还活着，但 60 秒内没有刷新文本文件。
请视为不健康并查看 `state\connector.log`；文本文件每 15 秒独立刷新一次，与连接状态无关，
因此过旧意味着进程卡死，而不仅仅是断线。

**PWA 显示 `/d/code/app` 而不是 `D:\code\app`** —— 这是预期行为，见
[工作区根目录在 PWA 中的显示形式](#工作区根目录在-pwa-中的显示形式)。
