package ext

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/shadow1ng/fscan/plugins"
)

// RunGuide 处理 `fscan guide [分类|关键词]`
func RunGuide(w io.Writer, args []string, noColor bool) int {
	if len(args) == 0 {
		printGuideOverview(w, noColor)
		return 0
	}

	query := strings.TrimSpace(strings.Join(args, " "))
	if cat := CategoryByKey(query); cat != nil {
		printCategory(w, cat, noColor, "")
		return 0
	}

	results := SearchCatalog(query)
	if len(results) == 0 {
		fmt.Fprintf(w, "未找到与 %q 匹配的合规场景。运行 `fscan guide` 查看全部分类，或 `fscan examples <模块名>` 查看具体模块示例。\n", query)
		return 0
	}
	fmt.Fprintf(w, "匹配到 %d 个场景（关键词: %s）：\n\n", len(results), query)
	lastCat := ""
	for _, r := range results {
		if r.Category.Key != lastCat {
			fmt.Fprintf(w, "── %s ──\n", colorize(noColor, color.FgHiGreen, r.Category.Title))
			lastCat = r.Category.Key
		}
		printItem(w, r.Item, noColor, query)
	}
	return 0
}

// RunExamples 处理 `fscan examples <模块名>`
func RunExamples(w io.Writer, args []string, noColor bool) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "用法: fscan examples <模块名>")
		fmt.Fprintln(w, "示例: fscan examples smb    fscan examples local    fscan examples proxy")
		fmt.Fprintln(w, "运行 `fscan -list-plugins` 查看当前构建全部可用模块。")
		return 0
	}
	name := strings.TrimSpace(args[0])

	// 1) 先在知识库里做关键词匹配（覆盖 proxy/local/web 等非插件概念）
	if results := SearchCatalog(name); len(results) > 0 {
		fmt.Fprintf(w, "「%s」相关合规排查命令：\n\n", name)
		for _, r := range results {
			printItem(w, r.Item, noColor, name)
		}
		return 0
	}

	// 2) 回退到真实插件注册表做动态核验，避免文档与上游实现脱节
	if plugins.Exists(name) {
		isLocal := plugins.HasType(name, plugins.PluginTypeLocal)
		isWeb := plugins.HasType(name, plugins.PluginTypeWeb)
		fmt.Fprintf(w, "模块 %q 已在当前构建注册。\n\n", name)
		switch {
		case isLocal:
			fmt.Fprintf(w, "  fscan -local %s\n", name)
		case isWeb:
			fmt.Fprintf(w, "  fscan -u http://<目标> -m %s -nobr -nopoc\n", name)
		default:
			fmt.Fprintf(w, "  fscan -h <目标> -m %s -nobr -nopoc    # 仅识别服务/Banner，默认端口以 -list-plugins 为准\n", name)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "说明：本扩展仅封装只读资产测绘命令。如需弱口令核验、漏洞POC验证或未授权访问探测，")
		fmt.Fprintln(w, "请在授权范围内直接使用 fscan 原生参数（-user/-pwd/-full/-pocpath 等），本扩展不做封装。")
		return 0
	}

	fmt.Fprintf(w, "未找到模块或关键词 %q。运行 `fscan -list-plugins` 查看全部可用模块，或 `fscan guide` 查看合规速查手册。\n", name)
	return 0
}

func printGuideOverview(w io.Writer, noColor bool) {
	fmt.Fprintln(w, colorize(noColor, color.FgHiGreen, "Fscan 合规速查手册"))
	fmt.Fprintln(w, ComplianceBanner)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "能力域总目录：")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, cat := range Categories {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", colorize(noColor, color.FgHiGreen, cat.Key), cat.Title, cat.Summary)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "常用合规速查 Top 命令：")
	top := topCommands(10)
	for _, c := range top {
		fmt.Fprintf(w, "  %s\n", c)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "用法：fscan guide <分类名|关键词>    例如：fscan guide scan    fscan guide 代理")
}

// topCommands 从各分类抽取前若干条代表性命令，用于总览页展示
func topCommands(n int) []string {
	var all []string
	for _, cat := range Categories {
		if cat.Key == "ext" {
			continue
		}
		for _, item := range cat.Items {
			if len(item.Commands) > 0 {
				all = append(all, strings.TrimSpace(strings.SplitN(item.Commands[0], "#", 2)[0]))
			}
		}
	}
	sort.Strings(all)
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func printCategory(w io.Writer, cat *Category, noColor bool, highlight string) {
	fmt.Fprintf(w, "%s — %s\n\n", colorize(noColor, color.FgHiGreen, cat.Title), cat.Summary)
	for i := range cat.Items {
		printItem(w, &cat.Items[i], noColor, highlight)
	}
}

func printItem(w io.Writer, item *Item, noColor bool, highlight string) {
	fmt.Fprintf(w, "• %s\n", colorize(noColor, color.FgHiWhite, item.Name))
	if item.Note != "" {
		fmt.Fprintf(w, "  避坑提示: %s\n", item.Note)
	}
	for _, cmd := range item.Commands {
		fmt.Fprintf(w, "    %s\n", highlightSubstr(cmd, highlight, noColor))
	}
	fmt.Fprintln(w)
}

func highlightSubstr(line, needle string, noColor bool) string {
	if noColor || needle == "" {
		return line
	}
	idx := strings.Index(strings.ToLower(line), strings.ToLower(needle))
	if idx < 0 {
		return line
	}
	end := idx + len(needle)
	return line[:idx] + color.New(color.FgHiYellow, color.Bold).Sprint(line[idx:end]) + line[end:]
}

func colorize(noColor bool, attr color.Attribute, s string) string {
	if noColor {
		return s
	}
	return color.New(attr).Sprint(s)
}
