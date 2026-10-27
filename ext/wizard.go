package ext

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// wizardScenario 是向导内的一个具体审计场景
type wizardScenario struct {
	Label     string   // 菜单展示文案
	Risk      string   // 风险级别标签
	Principle string   // 一句话合规原理说明
	BaseArgs  []string // 固定参数
	AskTarget bool      // 是否需要询问目标(-h)
	AskURL    bool      // 是否需要询问URL(-u)
	AskSocks5 bool      // 是否需要询问SOCKS5地址
	TargetTip string   // 目标输入提示语
	Default   string   // 回车时采用的默认值
}

type wizardCategory struct {
	Label     string
	Scenarios []wizardScenario
}

var wizardCategories = []wizardCategory{
	{
		Label: "网络资产存活与端口可达性测绘",
		Scenarios: []wizardScenario{
			{Label: "仅存活探测", Risk: "[无害]", Principle: "只做ICMP/TCP存活判断，不扫端口、不做任何凭据或POC验证。",
				BaseArgs: []string{"-ao"}, AskTarget: true, TargetTip: "扫描目标(CIDR/IP/范围)", Default: "127.0.0.1"},
			{Label: "常用端口扫描", Risk: "[无害]", Principle: "扫描内置常用端口集合并识别服务，禁用暴力破解与POC验证。",
				BaseArgs: []string{"-nobr", "-nopoc"}, AskTarget: true, TargetTip: "扫描目标(CIDR/IP/范围)", Default: "127.0.0.1"},
			{Label: "全端口扫描", Risk: "[无害]", Principle: "扫描1-65535全端口范围，适合资产测绘摸底，不做凭据或POC验证。",
				BaseArgs: []string{"-p", "1-65535", "-t", "800", "-nobr", "-nopoc"}, AskTarget: true, TargetTip: "扫描目标(CIDR/IP/范围)", Default: "127.0.0.1"},
		},
	},
	{
		Label: "Web资产指纹识别",
		Scenarios: []wizardScenario{
			{Label: "单URL指纹识别", Risk: "[无害]", Principle: "仅识别网站标题/中间件指纹，不加载任何漏洞POC。",
				BaseArgs: []string{"-m", "webtitle", "-nobr", "-nopoc"}, AskURL: true, TargetTip: "目标URL", Default: "http://127.0.0.1"},
		},
	},
	{
		Label: "挂审计代理内网穿透合规扫描",
		Scenarios: []wizardScenario{
			{Label: "SOCKS5代理扫描", Risk: "[无害]", Principle: "通过SOCKS5代理扫描内网；自动补齐-np跳过ICMP，避免代理链路下的存活误判。",
				BaseArgs: []string{"-np", "-nobr", "-nopoc", "-t", "200", "-time", "5"}, AskTarget: true, AskSocks5: true,
				TargetTip: "扫描目标(CIDR/IP/范围)", Default: "127.0.0.1"},
		},
	},
	{
		Label: "本地主机系统环境与基线自检",
		Scenarios: []wizardScenario{
			{Label: "系统信息自检", Risk: "[只读基线]", Principle: "仅读取本机系统信息，不发出任何网络探测包。", BaseArgs: []string{"-local", "systeminfo"}},
			{Label: "计划任务基线", Risk: "[只读基线]", Principle: "核查本机Windows计划任务配置基线。", BaseArgs: []string{"-local", "winschtask"}},
			{Label: "服务基线", Risk: "[只读基线]", Principle: "核查本机Windows服务配置基线。", BaseArgs: []string{"-local", "winservice"}},
			{Label: "定时任务基线", Risk: "[只读基线]", Principle: "核查本机crontab定时任务配置基线。", BaseArgs: []string{"-local", "crontask"}},
			{Label: "本地代理连通性自检", Risk: "[只读基线]", Principle: "本机启动SOCKS5代理服务用于链路自测。", BaseArgs: []string{"-local", "socks5proxy", "-start-socks5", "1080"}},
		},
	},
}

// RunWizard 启动交互式终端向导。返回值语义与 RunPreset 一致：
// launch=true 时 expanded 为最终展开参数，调用方应重写 os.Args 交还给原生扫描流程。
func RunWizard(in io.Reader, out io.Writer) (expanded []string, launch bool, exitCode int) {
	reader := bufio.NewReader(in)
	fmt.Fprintln(out, "Fscan 交互式安全合规审计向导（零命令记忆）")
	fmt.Fprintln(out, ComplianceBanner)
	fmt.Fprintln(out)

	for {
		fmt.Fprintln(out, "请选择安全审计大类：")
		for i, c := range wizardCategories {
			fmt.Fprintf(out, "  [%d] %s\n", i+1, c.Label)
		}
		fmt.Fprintln(out, "  [0] 退出")
		choice := promptLine(reader, out, "请输入编号: ")
		if choice == "0" || choice == "" {
			fmt.Fprintln(out, "已退出向导。")
			return nil, false, 0
		}
		catIdx := atoiOrDefault(choice, -1) - 1
		if catIdx < 0 || catIdx >= len(wizardCategories) {
			fmt.Fprintln(out, "无效编号，请重新选择。")
			continue
		}

		cat := wizardCategories[catIdx]
		fmt.Fprintf(out, "\n已选择: %s\n请选择具体审计场景：\n", cat.Label)
		for i, s := range cat.Scenarios {
			fmt.Fprintf(out, "  [%d] %s %s — %s\n", i+1, s.Label, s.Risk, s.Principle)
		}
		fmt.Fprintln(out, "  [0] 返回")
		sChoice := promptLine(reader, out, "请输入编号: ")
		if sChoice == "0" || sChoice == "" {
			fmt.Fprintln(out)
			continue
		}
		sIdx := atoiOrDefault(sChoice, -1) - 1
		if sIdx < 0 || sIdx >= len(cat.Scenarios) {
			fmt.Fprintln(out, "无效编号，请重新选择。")
			continue
		}

		scenario := cat.Scenarios[sIdx]
		args := append([]string{}, scenario.BaseArgs...)

		if scenario.AskTarget {
			target := promptLine(reader, out, fmt.Sprintf("%s [默认: %s]: ", scenario.TargetTip, scenario.Default))
			if target == "" {
				target = scenario.Default
			}
			args = append(args, "-h", target)
		}
		if scenario.AskURL {
			target := promptLine(reader, out, fmt.Sprintf("%s [默认: %s]: ", scenario.TargetTip, scenario.Default))
			if target == "" {
				target = scenario.Default
			}
			args = append(args, "-u", target)
		}
		if scenario.AskSocks5 {
			addr := promptLine(reader, out, "SOCKS5代理地址 [默认: 127.0.0.1:1080]: ")
			if addr == "" {
				addr = "127.0.0.1:1080"
			}
			args = append(args, "-socks5", addr)
		}
		outFile := ""
		if scenario.AskTarget || scenario.AskURL {
			outFile = promptLine(reader, out, "报告输出文件 [默认: audit.json，留空则不落盘]: ")
		}
		if outFile != "" {
			args = append(args, "-o", outFile, "-f", "json")
		}

		fmt.Fprintf(out, "\n生成审计命令: fscan %s\n", strings.Join(args, " "))
		fmt.Fprintln(out, "  [1] 立即执行  [2] 仅打印命令退出  [0] 返回重选")
		confirm := promptLine(reader, out, "请输入编号: ")
		switch confirm {
		case "1":
			return args, true, 0
		case "2":
			return nil, false, 0
		default:
			fmt.Fprintln(out)
			continue
		}
	}
}

func promptLine(reader *bufio.Reader, out io.Writer, prompt string) string {
	fmt.Fprint(out, prompt)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func atoiOrDefault(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	return n
}
