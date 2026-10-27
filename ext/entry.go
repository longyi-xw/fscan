package ext

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/shadow1ng/fscan/common"
)

// PreHandleCLI 是上游 main_cli.go 唯一需要插入的前置拦截点。
// 命中扩展子命令时自行处理并通过 handled=true 要求调用方直接退出；
// 命中 preset/wizard 的"执行"分支时，原地重写 *argv 并返回 handled=false，
// 由调用方无缝交给原生 common.Flag(&info) + core.RunScan 在同一进程内继续执行。
func PreHandleCLI(argv *[]string) (handled bool, exitCode int) {
	args := *argv
	if len(args) < 2 {
		return false, 0
	}

	// 子命令前的全局flag在此阶段尚未解析，-nocolor 需要自行在原始参数里探测
	noColor := hasFlag(args, "-nocolor")

	switch args[1] {
	case "guide":
		return true, RunGuide(os.Stdout, args[2:], noColor)
	case "examples":
		return true, RunExamples(os.Stdout, args[2:], noColor)
	case "preset":
		merged, done, code := RunPreset(os.Stdout, os.Stderr, args[2:])
		if !done {
			*argv = append([]string{args[0]}, merged...)
			return false, 0
		}
		return true, code
	case "wizard", "-ui":
		merged, launch, code := RunWizard(os.Stdin, os.Stdout)
		if launch {
			*argv = append([]string{args[0]}, merged...)
			return false, 0
		}
		return true, code
	case "update":
		return true, RunUpdate(os.Stdout, os.Stderr, args[2:])
	}
	return false, 0
}

// PrintQuickFooter 在官方原生帮助输出末尾追加扩展快捷指令导航框。
// 必须在 common.Flag(&info) 返回 common.ErrShowHelp 之后调用——此时flag已解析完毕，
// 可以安全读取 common.GetFlagVars() 获取真实的 -nocolor/-silent 状态。
func PrintQuickFooter() {
	fv := common.GetFlagVars()
	if fv.Silent {
		return
	}
	noColor := fv.NoColor

	title := "Fscan-Ext 合规扩展快捷指令"
	lines := []string{
		"fscan guide [分类|关键词]      查看八大安全合规能力速查字典",
		"fscan examples <模块名>        查看指定模块的合规排查命令集",
		"fscan preset [预设名] [参数]   一键安全合规场景预设（运行 fscan preset 看全部）",
		"fscan wizard (别名 -ui)        交互式终端审计向导，零命令记忆",
		"fscan update [--check|--push]  一键同步官方源码并安全升级本机 fscan",
	}

	maxLen := len([]rune(title))
	for _, l := range lines {
		if n := len([]rune(l)); n > maxLen {
			maxLen = n
		}
	}
	top := "┌" + repeat("─", maxLen+2) + "┐"
	bottom := "└" + repeat("─", maxLen+2) + "┘"

	fmt.Println()
	fmt.Println(top)
	printBoxed(title, maxLen, noColor, color.FgHiGreen, true)
	for _, l := range lines {
		printBoxed(l, maxLen, noColor, color.FgGreen, false)
	}
	fmt.Println(bottom)
}

func printBoxed(text string, width int, noColor bool, attr color.Attribute, bold bool) {
	pad := width - len([]rune(text))
	if pad < 0 {
		pad = 0
	}
	line := "│ " + text + repeat(" ", pad) + " │"
	if noColor {
		fmt.Println(line)
		return
	}
	c := color.New(attr)
	if bold {
		c.Add(color.Bold)
	}
	fmt.Print("│ ")
	_, _ = c.Print(text)
	fmt.Println(repeat(" ", pad) + " │")
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
