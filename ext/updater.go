package ext

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// 以下两个变量的默认值通过编译期 -ldflags -X 注入，运行时仍可通过
// --repo/--bin 命令行参数或 FSCAN_EXT_REPO/FSCAN_EXT_BIN 环境变量覆盖。
var (
	DefaultRepoDir    = `D:\dev\go\fscan`
	DefaultInstallBin = `D:\software\tools\fscan.exe`
)

const upstreamURL = "https://github.com/shadow1ng/fscan.git"

// CleanOldBinary 静默清理上次热更新遗留的 .old 文件。设计为在 main() 入口无条件调用，
// 不返回错误、不产生任何输出——文件不存在是最常见的正常情况。
func CleanOldBinary() {
	bin := resolveInstallBin(nil)
	if bin == "" {
		return
	}
	_ = os.Remove(bin + ".old")
}

func resolveFlag(args []string, name string) string {
	prefix := "--" + name + "="
	for i, a := range args {
		if a == "--"+name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

func resolveRepoDir(args []string) string {
	if v := resolveFlag(args, "repo"); v != "" {
		return v
	}
	if v := os.Getenv("FSCAN_EXT_REPO"); v != "" {
		return v
	}
	return DefaultRepoDir
}

func resolveInstallBin(args []string) string {
	if v := resolveFlag(args, "bin"); v != "" {
		return v
	}
	if v := os.Getenv("FSCAN_EXT_BIN"); v != "" {
		return v
	}
	return DefaultInstallBin
}

// runCmd 在指定目录执行命令，返回合并后的标准输出/错误
func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func ensureUpstreamRemote(repoDir string) error {
	if _, err := runCmd(repoDir, "git", "remote", "get-url", "upstream"); err == nil {
		return nil
	}
	_, err := runCmd(repoDir, "git", "remote", "add", "upstream", upstreamURL)
	return err
}

func isGitRepo(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (info.IsDir() || info.Mode().IsRegular())
}

// RunUpdate 处理 `fscan update [--check|--push] [--repo=DIR] [--bin=PATH]`
func RunUpdate(stdout, stderr io.Writer, args []string) int {
	repoDir := resolveRepoDir(args)
	bin := resolveInstallBin(args)
	checkOnly := hasFlag(args, "--check")
	push := hasFlag(args, "--push")

	if !isGitRepo(repoDir) {
		fmt.Fprintf(stderr, "[Fscan-Ext] %s 不是一个git仓库，无法执行更新。可用 --repo=<目录> 或 FSCAN_EXT_REPO 指定。\n", repoDir)
		return 1
	}

	fmt.Fprintf(stdout, "[Fscan-Ext] 源码仓库: %s\n[Fscan-Ext] 安装目标: %s\n", repoDir, bin)

	if err := ensureUpstreamRemote(repoDir); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 配置 upstream 远端失败: %v\n", err)
		return 1
	}
	if out, err := runCmd(repoDir, "git", "fetch", "upstream", "--tags"); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] git fetch upstream 失败:\n%s\n", out)
		return 1
	}

	behindOut, _ := runCmd(repoDir, "git", "log", "--oneline", "HEAD..upstream/main")
	behind := nonEmptyLines(behindOut)
	if len(behind) == 0 {
		fmt.Fprintln(stdout, "[Fscan-Ext] 已是最新，没有落后 upstream/main 的提交。")
		if checkOnly {
			return 0
		}
		return 0
	}
	fmt.Fprintf(stdout, "[Fscan-Ext] 落后 upstream/main 共 %d 个提交：\n", len(behind))
	for _, l := range behind {
		fmt.Fprintf(stdout, "    %s\n", l)
	}

	if checkOnly {
		return 0
	}

	// 若工作区有未提交修改，先 stash
	statusOut, _ := runCmd(repoDir, "git", "status", "--porcelain")
	stashed := strings.TrimSpace(statusOut) != ""
	if stashed {
		if out, err := runCmd(repoDir, "git", "stash", "push", "-u", "-m", "fscan-ext-auto-stash"); err != nil {
			fmt.Fprintf(stderr, "[Fscan-Ext] git stash 失败:\n%s\n", out)
			return 1
		}
		fmt.Fprintln(stdout, "[Fscan-Ext] 工作区有未提交修改，已自动 stash。")
	}
	restoreStash := func() {
		if !stashed {
			return
		}
		if out, err := runCmd(repoDir, "git", "stash", "pop"); err != nil {
			fmt.Fprintf(stderr, "[Fscan-Ext] 警告: git stash pop 失败，改动仍保留在 stash 中，请手动执行 git stash list / git stash pop。\n%s\n", out)
		}
	}

	if out, err := runCmd(repoDir, "git", "merge", "upstream/main", "--no-edit"); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 合并发生冲突，已自动回滚，工作区保持干净：\n%s\n", out)
		_, _ = runCmd(repoDir, "git", "merge", "--abort")
		restoreStash()
		return 1
	}
	fmt.Fprintln(stdout, "[Fscan-Ext] 已成功合并 upstream/main。")
	restoreStash()

	if out, err := runCmd(repoDir, "go", "mod", "download"); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] go mod download 失败:\n%s\n", out)
		return 1
	}
	if out, err := runCmd(repoDir, "go", "test", "-vet=off", "./ext/..."); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 扩展层测试未通过，已中止更新，本机 fscan.exe 未被改动：\n%s\n", out)
		return 1
	}
	fmt.Fprintln(stdout, "[Fscan-Ext] 扩展层测试通过。")

	commitShort, _ := runCmd(repoDir, "git", "rev-parse", "--short", "HEAD")
	commitShort = strings.TrimSpace(commitShort)
	buildDate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	newBin := filepath.Join(repoDir, "fscan.new.exe")
	ldflags := fmt.Sprintf("-s -w -X github.com/shadow1ng/fscan/common.commit=%s -X github.com/shadow1ng/fscan/common.date=%s",
		commitShort, buildDate)
	if out, err := runCmd(repoDir, "go", "build", "-trimpath", "-ldflags", ldflags, "-o", newBin, "."); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 编译失败，本机 fscan.exe 未被改动：\n%s\n", out)
		return 1
	}
	fmt.Fprintf(stdout, "[Fscan-Ext] 编译完成: %s (commit %s)\n", newBin, commitShort)

	if err := hotSwapBinary(newBin, bin); err != nil {
		fmt.Fprintf(stderr, "[Fscan-Ext] 热替换失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "[Fscan-Ext] 已安全替换 %s，旧版本保留为 %s.old（下次启动时自动清理）。\n", bin, bin)

	if push {
		if out, err := runCmd(repoDir, "git", "push", "origin", "main"); err != nil {
			fmt.Fprintf(stderr, "[Fscan-Ext] git push origin main 失败:\n%s\n", out)
			return 1
		}
		fmt.Fprintln(stdout, "[Fscan-Ext] 已推送合并结果到 origin/main。")
	}

	return 0
}

// hotSwapBinary 实现 Windows 下运行中 exe 的原子热替换：
// 1) 删除可能存在的旧 .old 2) 把当前运行中的二进制改名为 .old（Windows允许）
// 3) 把新编译的二进制移动到目标路径。任意一步失败都尽力回滚。
func hotSwapBinary(newBin, targetBin string) error {
	oldBin := targetBin + ".old"
	_ = os.Remove(oldBin)

	renamedOld := false
	if _, err := os.Stat(targetBin); err == nil {
		if err := os.Rename(targetBin, oldBin); err != nil {
			return fmt.Errorf("无法重命名当前运行中的二进制 %s -> %s: %w", targetBin, oldBin, err)
		}
		renamedOld = true
	}

	if err := os.Rename(newBin, targetBin); err != nil {
		if renamedOld {
			_ = os.Rename(oldBin, targetBin) // 回滚
		}
		return fmt.Errorf("无法将新二进制移动到 %s: %w", targetBin, err)
	}
	return nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
