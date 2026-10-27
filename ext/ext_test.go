package ext

import (
	"bytes"
	"strings"
	"testing"
)

func TestMergeArgs_UserOverridesPresetDefault(t *testing.T) {
	defaults := []string{"-nobr", "-nopoc", "-t", "100", "-rate", "200"}
	user := []string{"-h", "192.168.1.0/24", "-t", "50"}

	got := mergeArgs(defaults, user)
	gotStr := strings.Join(got, " ")

	if strings.Contains(gotStr, "-t 100") {
		t.Fatalf("expected user -t 50 to override preset default -t 100, got: %s", gotStr)
	}
	if !strings.Contains(gotStr, "-t 50") {
		t.Fatalf("expected user -t 50 present, got: %s", gotStr)
	}
	for _, want := range []string{"-nobr", "-nopoc", "-rate", "200", "-h", "192.168.1.0/24"} {
		if !strings.Contains(gotStr, want) {
			t.Fatalf("expected %q in merged args, got: %s", want, gotStr)
		}
	}
}

func TestMergeArgs_BooleanFlagNotGreedyWithNextFlag(t *testing.T) {
	// -nobr 后紧跟另一个flag "-h"，不应把"-h"当成-nobr的值
	got := mergeArgs([]string{"-nobr"}, []string{"-h", "127.0.0.1"})
	gotStr := strings.Join(got, " ")
	if !strings.Contains(gotStr, "-nobr") || !strings.Contains(gotStr, "-h 127.0.0.1") {
		t.Fatalf("unexpected merge result: %s", gotStr)
	}
}

func TestExtractDryRun(t *testing.T) {
	dryRun, rest := extractDryRun([]string{"-h", "127.0.0.1", "--dry-run"})
	if !dryRun {
		t.Fatal("expected dryRun=true")
	}
	if strings.Join(rest, " ") != "-h 127.0.0.1" {
		t.Fatalf("unexpected rest: %v", rest)
	}

	dryRun2, rest2 := extractDryRun([]string{"-h", "127.0.0.1"})
	if dryRun2 {
		t.Fatal("expected dryRun=false")
	}
	if len(rest2) != 2 {
		t.Fatalf("expected rest unchanged, got: %v", rest2)
	}
}

func TestRunPreset_Unknown(t *testing.T) {
	var out, errBuf bytes.Buffer
	_, handled, code := RunPreset(&out, &errBuf, []string{"does-not-exist"})
	if !handled || code != 1 {
		t.Fatalf("expected handled=true code=1, got handled=%v code=%d", handled, code)
	}
	if !strings.Contains(errBuf.String(), "未知预设") {
		t.Fatalf("expected error message on stderr, got: %s", errBuf.String())
	}
}

func TestRunPreset_ListWhenEmpty(t *testing.T) {
	var out, errBuf bytes.Buffer
	_, handled, code := RunPreset(&out, &errBuf, nil)
	if !handled || code != 0 {
		t.Fatalf("expected handled=true code=0, got handled=%v code=%d", handled, code)
	}
	if !strings.Contains(out.String(), "可用安全合规场景预设") {
		t.Fatalf("expected preset list on stdout, got: %s", out.String())
	}
}

func TestRunPreset_DryRunGoesToStdoutNotStderr(t *testing.T) {
	var out, errBuf bytes.Buffer
	expanded, handled, code := RunPreset(&out, &errBuf, []string{"stealth", "-h", "127.0.0.1", "--dry-run"})
	if !handled || code != 0 || expanded != nil {
		t.Fatalf("unexpected dry-run result: handled=%v code=%d expanded=%v", handled, code, expanded)
	}
	if !strings.Contains(out.String(), "[Fscan-Ext]") {
		t.Fatalf("expected announcement on stdout for dry-run, got: %s", out.String())
	}
	if errBuf.Len() != 0 {
		t.Fatalf("dry-run must not write to stderr, got: %s", errBuf.String())
	}
}

func TestRunPreset_RealExecutionAnnouncementGoesToStderr(t *testing.T) {
	var out, errBuf bytes.Buffer
	expanded, handled, code := RunPreset(&out, &errBuf, []string{"quick", "-h", "127.0.0.1"})
	if handled || code != 0 {
		t.Fatalf("expected handled=false for real execution handoff, got handled=%v code=%d", handled, code)
	}
	if out.Len() != 0 {
		t.Fatalf("real execution must not write to stdout (keep -silent NDJSON clean), got: %s", out.String())
	}
	if !strings.Contains(errBuf.String(), "[Fscan-Ext]") {
		t.Fatalf("expected announcement on stderr, got: %s", errBuf.String())
	}
	gotStr := strings.Join(expanded, " ")
	for _, want := range []string{"-nobr", "-nopoc", "-h", "127.0.0.1"} {
		if !strings.Contains(gotStr, want) {
			t.Fatalf("expected %q in expanded args, got: %s", want, gotStr)
		}
	}
}

func TestAllPresets_CarryNoBruteNoPocUnlessLocalOrAliveOnly(t *testing.T) {
	for _, p := range Presets {
		s := strings.Join(p.Args, " ")
		isLocalOrAliveOnly := strings.Contains(s, "-local") || strings.Contains(s, "-ao")
		if isLocalOrAliveOnly {
			continue
		}
		if !strings.Contains(s, "-nobr") || !strings.Contains(s, "-nopoc") {
			t.Fatalf("preset %q must disable brute-force and POC by default, got args: %s", p.Name, s)
		}
	}
}

func TestSearchCatalog_FuzzyChineseAndEnglish(t *testing.T) {
	if res := SearchCatalog("代理"); len(res) == 0 {
		t.Fatal("expected at least one match for 代理")
	}
	if res := SearchCatalog("redis"); len(res) != 0 {
		// redis 不在本扩展的知识库范围内（弱口令/未授权检测已排除），不应命中任何预置场景
		t.Fatalf("expected no catalog match for out-of-scope keyword 'redis', got: %v", res)
	}
	if res := SearchCatalog("proxy"); len(res) == 0 {
		t.Fatal("expected at least one match for proxy")
	}
}

func TestCategoryByKey(t *testing.T) {
	if CategoryByKey("scan") == nil {
		t.Fatal("expected scan category to exist")
	}
	if CategoryByKey("auth-audit") != nil {
		t.Fatal("auth-audit category must not exist in the narrowed-scope build")
	}
	if CategoryByKey("vuln-audit") != nil {
		t.Fatal("vuln-audit category must not exist in the narrowed-scope build")
	}
}

func TestRunGuide_UnknownKeyword(t *testing.T) {
	var out bytes.Buffer
	code := RunGuide(&out, []string{"this-keyword-does-not-exist-anywhere"}, true)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "未找到") {
		t.Fatalf("expected graceful not-found message, got: %s", out.String())
	}
}

func TestRunExamples_LocalModule(t *testing.T) {
	var out bytes.Buffer
	code := RunExamples(&out, []string{"local"}, true)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "-local") {
		t.Fatalf("expected -local examples, got: %s", out.String())
	}
}

func TestTokenizeArgs_EqualsForm(t *testing.T) {
	toks := tokenizeArgs([]string{"--repo=D:\\dev\\go\\fscan"})
	if len(toks) != 1 || toks[0].flag != "--repo" || toks[0].value != "D:\\dev\\go\\fscan" {
		t.Fatalf("unexpected tokenization: %+v", toks)
	}
}

func TestResolveRepoDir_Override(t *testing.T) {
	got := resolveRepoDir([]string{"--repo=C:\\somewhere"})
	if got != "C:\\somewhere" {
		t.Fatalf("expected override to take effect, got: %s", got)
	}
}
