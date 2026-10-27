package ext

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Preset 是一个一键安全合规场景预设
type Preset struct {
	Name    string   // 预设名
	Summary string   // 适用场景
	Level   string   // 合规审计级别
	Args    []string // 底层等效展开参数（不含目标，目标由用户追加）
}

// Presets 内置合规场景预设清单。
//
// 范围声明：每一条预设都显式携带 -nobr -nopoc（除 -ao/-local 这类本身就不触达
// 弱口令或POC逻辑的场景），确保一键执行的默认行为始终是"只读资产测绘/基线自检"，
// 不会意外触发凭据核验或漏洞验证。
var Presets = []Preset{
	{
		Name:    "alive",
		Summary: "网络资产快速存活与可达性测绘",
		Level:   "[无害资产测绘]",
		Args:    []string{"-ao"},
	},
	{
		Name:    "stealth",
		Summary: "低噪温和资产排查，禁用暴破与POC，限制并发保障业务稳定",
		Level:   "[无害资产测绘]",
		Args:    []string{"-nobr", "-nopoc", "-t", "100", "-rate", "200"},
	},
	{
		Name:    "quick",
		Summary: "日常安全合规巡检摸底：常用端口+服务识别，禁用暴破与POC",
		Level:   "[无害资产测绘]",
		Args:    []string{"-nobr", "-nopoc"},
	},
	{
		Name:    "full-port",
		Summary: "全端口网络服务开放性深度资产测绘",
		Level:   "[无害资产测绘]",
		Args:    []string{"-p", "1-65535", "-t", "800", "-nobr", "-nopoc"},
	},
	{
		Name:    "proxy-scan",
		Summary: "SOCKS5代理穿透审计扫描，自动补齐 -np 避免存活误判",
		Level:   "[无害资产测绘]",
		Args:    []string{"-np", "-nobr", "-nopoc", "-t", "200", "-time", "5"},
	},
	{
		Name:    "host-recon",
		Summary: "本地主机操作系统环境与软硬件配置自检（仅本机，不触达网络）",
		Level:   "[只读基线审计]",
		Args:    []string{"-local", "systeminfo"},
	},
	{
		Name:    "socks5-local-test",
		Summary: "本地SOCKS5代理服务连通性自检（仅本机，不触达网络）",
		Level:   "[只读基线审计]",
		Args:    []string{"-local", "socks5proxy", "-start-socks5", "1080"},
	},
	{
		Name:    "json-silent",
		Summary: "静默结构化NDJSON/JSON审计结果落盘模式（配合其他参数或目标使用）",
		Level:   "[无害资产测绘]",
		Args:    []string{"-silent", "-nobr", "-nopoc", "-f", "json", "-o", "audit_result.json"},
	},
}

// FindPreset 按名称查找预设
func FindPreset(name string) *Preset {
	for i := range Presets {
		if Presets[i].Name == name {
			return &Presets[i]
		}
	}
	return nil
}

// ListPresets 打印全部预设清单
func ListPresets(w io.Writer) {
	fmt.Fprintln(w, "可用安全合规场景预设：")
	fmt.Fprintln(w, ComplianceBanner)
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "预设名\t合规级别\t适用场景\t等效展开参数")
	for _, p := range Presets {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.Level, p.Summary, strings.Join(p.Args, " "))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "用法: fscan preset <预设名> [目标与自定义追加参数] [--dry-run]")
	fmt.Fprintln(w, "示例: fscan preset stealth -h 192.168.1.0/24 --dry-run")
}

// tok 是一次参数token化的结果：一个flag及其可选的值
type tok struct {
	flag     string
	value    string
	hasValue bool
}

// tokenizeArgs 将 fscan 风格的单横线参数切片解析为 token 序列。
// 规则：
//   - "-flag=value" -> flag/value
//   - "-flag value"（value 不以"-"开头）-> flag/value，消耗两个位置
//   - "-flag"（后面没有值或紧跟另一个flag）-> 纯布尔token
//   - 不以"-"开头的裸值（极少见）原样保留，flag为空
func tokenizeArgs(args []string) []tok {
	var out []tok
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			out = append(out, tok{value: a, hasValue: true})
			continue
		}
		if eq := strings.Index(a, "="); eq >= 0 {
			out = append(out, tok{flag: a[:eq], value: a[eq+1:], hasValue: true})
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, tok{flag: a, value: args[i+1], hasValue: true})
			i++
			continue
		}
		out = append(out, tok{flag: a})
	}
	return out
}

// mergeArgs 将预设默认参数与用户追加参数合并，用户传入的同名 Flag 优先级更高
// （自动去重覆盖），未冲突的默认参数保留原有顺序，用户独有参数追加在末尾。
func mergeArgs(defaults, user []string) []string {
	dTok := tokenizeArgs(defaults)
	uTok := tokenizeArgs(user)

	userFlags := make(map[string]bool, len(uTok))
	for _, t := range uTok {
		if t.flag != "" {
			userFlags[t.flag] = true
		}
	}

	emit := func(out []string, t tok) []string {
		if t.flag != "" {
			out = append(out, t.flag)
		}
		if t.hasValue {
			out = append(out, t.value)
		}
		return out
	}

	var out []string
	for _, t := range dTok {
		if t.flag != "" && userFlags[t.flag] {
			continue // 用户显式传入同名flag，跳过预设默认值
		}
		out = emit(out, t)
	}
	for _, t := range uTok {
		out = emit(out, t)
	}
	return out
}

// extractDryRun 从参数中剥离 --dry-run 标记
func extractDryRun(args []string) (dryRun bool, rest []string) {
	for _, a := range args {
		if a == "--dry-run" {
			dryRun = true
			continue
		}
		rest = append(rest, a)
	}
	return dryRun, rest
}

// RunPreset 处理 `fscan preset [预设名] [目标与追加参数] [--dry-run]`。
// args 为 "preset" 之后的全部剩余参数。
//
// 返回值：
//   - expanded: 展开后的完整 fscan 参数切片（仅当 handled=false 时有意义，
//     调用方应将其重写进 os.Args 并把控制权交还给原生 common.Flag/core.RunScan）
//   - handled: true 表示本次调用已经处理完毕（打印了列表/错误/dry-run结果），
//     调用方直接用 exitCode 退出，不再进入原生扫描流程
//   - exitCode: 进程退出码
func RunPreset(stdout, stderr io.Writer, args []string) (expanded []string, handled bool, exitCode int) {
	if len(args) == 0 {
		ListPresets(stdout)
		return nil, true, 0
	}

	name := args[0]
	preset := FindPreset(name)
	if preset == nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 未知预设: %q\n\n", name)
		ListPresets(stderr)
		return nil, true, 1
	}

	dryRun, rest := extractDryRun(args[1:])
	merged := mergeArgs(preset.Args, rest)
	line := fmt.Sprintf("[Fscan-Ext] 安全预设 %s [%s] -> 展开等效命令: fscan %s",
		preset.Level, name, strings.Join(merged, " "))

	if dryRun {
		fmt.Fprintln(stdout, line)
		return nil, true, 0
	}

	// 真实执行：提示信息写 stderr，保证 -silent 场景下 stdout 仅有原生 NDJSON 输出
	fmt.Fprintln(stderr, line)
	return merged, false, 0
}
