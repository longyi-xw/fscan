# Fscan-Ext 零侵入式合规增强扩展

本扩展包（`ext/`）为 [shadow1ng/fscan](https://github.com/shadow1ng/fscan) 提供命令行合规速查字典、
一键场景预设、交互式终端向导与自动合并更新，采用完全独立的目录架构，不修改任何上游核心文件
（`common/flag.go`、`core/`、`plugins/`、`webscan/`、`README.md` 均保持原样）。

## 能力边界（请先读这一节）

本扩展**仅**覆盖以下四个合规场景域：

| 领域 | 说明 |
|------|------|
| `scan` | 资产测绘与网络可达性（存活探测、端口扫描、服务识别、Web指纹） |
| `io` | 输入输出与结构化审计报告（目标导入、排除规则、多格式输出、静默NDJSON） |
| `net` | 代理穿透扫描与业务友好型限速控制 |
| `host-audit` | 本地主机安全基线自检（仅本机，不触达任何远程目标） |

**明确不提供**：弱口令字典管理/暴力破解向导、漏洞POC验证预设（MS17-010/SMBGhost/webpoc）、
未授权访问探测类场景封装。这些能力本身存在于 fscan 原生参数中（`-user/-pwd/-userf/-pwdf/
-full/-pocpath` 等），如确有授权测试需要，请在授权范围内直接使用原生参数——本扩展不做任何
改动、封装或限制，但也不会主动引导/简化这类操作。

## 目录结构

```text
ext/
├── entry.go      # CLI前置拦截分发器 + 默认帮助尾注增强 + 旧二进制清理
├── catalog.go    # 四大合规能力域知识库与命令模板（经上游真实flag/插件注册表核对）
├── guide.go      # fscan guide / fscan examples
├── presets.go    # fscan preset 一键场景预设引擎
├── wizard.go     # fscan wizard（别名 -ui）交互式终端向导
├── updater.go    # fscan update 自动合并编译热替换
├── ext_test.go   # 单元测试
└── scripts/
    └── update-fscan.ps1   # 外部兜底更新脚本（fscan.exe不可用时使用）
```

上游唯一的改动点是 `main_cli.go` 的 `run()` 函数，新增 5 行调用（`ext.CleanOldBinary()`、
`ext.PreHandleCLI(&os.Args)` 拦截、`ext.PrintQuickFooter()`），其余逻辑完全不变。

## 命令一览

```bash
fscan                      # 原生帮助 + 扩展快捷指令导航框
fscan guide [分类|关键词]    # 速查手册：scan / io / net / host-audit / ext
fscan examples <模块名>     # 指定模块的合规排查命令集（同时核验真实插件注册表）
fscan preset                # 查看全部预设
fscan preset <名称> [目标与追加参数] [--dry-run]
fscan wizard                # 交互式向导（别名 -ui）
fscan update [--check|--push] [--repo=DIR] [--bin=PATH]
```

### 内置预设

| 预设 | 合规级别 | 等效参数 |
|------|----------|----------|
| `alive` | 无害资产测绘 | `-ao` |
| `stealth` | 无害资产测绘 | `-nobr -nopoc -t 100 -rate 200` |
| `quick` | 无害资产测绘 | `-nobr -nopoc` |
| `full-port` | 无害资产测绘 | `-p 1-65535 -t 800 -nobr -nopoc` |
| `proxy-scan` | 无害资产测绘 | `-np -nobr -nopoc -t 200 -time 5` |
| `host-recon` | 只读基线审计 | `-local systeminfo` |
| `socks5-local-test` | 只读基线审计 | `-local socks5proxy -start-socks5 1080` |
| `json-silent` | 无害资产测绘 | `-silent -nobr -nopoc -f json -o audit_result.json` |

除 `-local` / `-ao` 场景外，**每个预设都显式携带 `-nobr -nopoc`**，确保一键执行的默认行为
始终是只读资产测绘，不会意外触发凭据核验或漏洞验证（单测 `TestAllPresets_CarryNoBruteNoPocUnlessLocalOrAliveOnly` 对此做了强制校验）。

用户追加的同名 Flag 优先级高于预设默认值（自动去重覆盖）。例如：

```bash
fscan preset stealth -h 192.168.1.0/24 -t 50 --dry-run
# -> fscan -nobr -nopoc -rate 200 -t 50 -h 192.168.1.0/24   （用户的 -t 50 覆盖了预设默认的 -t 100）
```

### `-silent` 纯净性保证

`fscan preset`/`wizard` 的"正在执行"提示信息一律写 **stderr**，`--dry-run` 的展开结果写
**stdout**（此时并未启动真实扫描，不存在 NDJSON 污染问题）。`-silent` 模式下原生扫描的
stdout 输出未被本扩展触碰，始终保持纯 NDJSON。

## `fscan update` 工作原理

1. 确保 `upstream` 远端存在（指向 `https://github.com/shadow1ng/fscan.git`），`git fetch upstream --tags`。
2. 工作区若有未提交修改，自动 `git stash push -u`，流程结束后自动恢复。
3. `git merge upstream/main --no-edit`；一旦冲突立即 `git merge --abort` 回滚，绝不留下破损工作区。
4. `go mod download` + `go test -vet=off ./ext/...` 校验扩展层完好。
5. `go build -trimpath -ldflags="-s -w -X .../common.commit=<短SHA> -X .../common.date=<时间>" -o fscan.new.exe .`
6. **Windows 热替换**（运行中的 exe 无法直接覆盖写入）：
   删除残留的 `fscan.exe.old` → 将当前运行中的 `fscan.exe` `os.Rename` 为 `fscan.exe.old`
   （Windows 允许对运行中的 exe 改名）→ 将新二进制 `os.Rename` 到目标路径。
   下次任意启动 `fscan` 时，`ext.CleanOldBinary()` 自动静默删除遗留的 `.old` 文件。
7. `--push` 时执行 `git push origin main`。

默认路径：源码仓库 `D:\dev\go\fscan`，安装路径 `D:\software\tools\fscan.exe`；可用
`--repo=`/`--bin=` 或环境变量 `FSCAN_EXT_REPO`/`FSCAN_EXT_BIN` 覆盖，也可通过编译期
`-ldflags -X` 注入新的默认值（`ext.DefaultRepoDir` / `ext.DefaultInstallBin`）。

若本机 `fscan.exe` 因故不可用，可直接运行独立兜底脚本：

```powershell
powershell -File ext\scripts\update-fscan.ps1 -Check
powershell -File ext\scripts\update-fscan.ps1
powershell -File ext\scripts\update-fscan.ps1 -Push
```

## 本机环境注意事项（开发者笔记）

- Go 工具链、模块缓存、构建缓存均已通过用户级环境变量重定向到 `D:\software\...`，不落 C 盘
  （`GOPATH`/`GOMODCACHE`/`GOCACHE`/`GOPROXY`/`GOTELEMETRYDIR`）。修改这些环境变量后需要
  **打开一个新的终端窗口**才会生效（Windows 用户级环境变量不会影响已打开的旧终端）。
- 本机编译大型 Go 项目时偶发 `out of memory` / `VirtualAlloc failed`（系统页面文件压力），
  属已知的瞬时资源问题，重试一次通常即可通过；用 `go build -p=1` 降低编译并行度可减少复现概率。
- Windows Defender 对新编译的 fscan 二进制（尤其是 `-ldflags="-s -w"` 去符号表的产物）偶发
  实时防护误报拦截，属已知的渗透测试工具类通用启发式误报；本扩展**不会**自动修改 Defender
  配置（这类系统安全设置变更需要用户自行决定并执行），重试编译通常可绕过误报；若持续被拦截，
  需要用户自行在 Defender 设置中为构建目录添加排除项。

## 测试

```bash
go test -vet=off ./ext/...
```
