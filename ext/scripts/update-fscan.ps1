<#
.SYNOPSIS
    独立兜底脚本：拉取官方 shadow1ng/fscan 最新源码、合并、测试、编译并安全替换本机 fscan.exe。

    这是 `fscan update` 子命令的外部等价物——当本机 fscan.exe 因故无法运行（例如正在被
    热替换过程中意外损坏）时，仍可直接运行本脚本完成同样的流水线，不依赖已安装的 fscan.exe。

.PARAMETER RepoDir
    本地源码仓库目录，默认 D:\dev\go\fscan（可用 FSCAN_EXT_REPO 环境变量覆盖）。

.PARAMETER InstallBin
    本机安装路径，默认 D:\software\tools\fscan.exe（可用 FSCAN_EXT_BIN 环境变量覆盖）。

.PARAMETER Check
    仅检查 upstream 是否有新提交，不执行合并编译。

.PARAMETER Push
    合并编译成功后，推送到 origin/main。

.EXAMPLE
    powershell -File ext\scripts\update-fscan.ps1 -Check
    powershell -File ext\scripts\update-fscan.ps1
    powershell -File ext\scripts\update-fscan.ps1 -Push
#>
param(
    [string]$RepoDir = $(if ($env:FSCAN_EXT_REPO) { $env:FSCAN_EXT_REPO } else { "D:\dev\go\fscan" }),
    [string]$InstallBin = $(if ($env:FSCAN_EXT_BIN) { $env:FSCAN_EXT_BIN } else { "D:\software\tools\fscan.exe" }),
    [switch]$Check,
    [switch]$Push
)

$ErrorActionPreference = "Stop"
$UpstreamUrl = "https://github.com/shadow1ng/fscan.git"

function Write-Ext($msg) { Write-Host "[Fscan-Ext] $msg" }

function Invoke-Git {
    param([string[]]$Args)
    $out = & git -C $RepoDir @Args 2>&1
    return @{ Output = ($out -join "`n"); Code = $LASTEXITCODE }
}

if (-not (Test-Path (Join-Path $RepoDir ".git"))) {
    Write-Error "$RepoDir 不是一个 git 仓库，无法执行更新。请用 -RepoDir 指定正确路径。"
    exit 1
}

Write-Ext "源码仓库: $RepoDir"
Write-Ext "安装目标: $InstallBin"

$remoteCheck = Invoke-Git @("remote", "get-url", "upstream")
if ($remoteCheck.Code -ne 0) {
    $addRemote = Invoke-Git @("remote", "add", "upstream", $UpstreamUrl)
    if ($addRemote.Code -ne 0) { Write-Error "配置 upstream 远端失败:`n$($addRemote.Output)"; exit 1 }
}

$fetch = Invoke-Git @("fetch", "upstream", "--tags")
if ($fetch.Code -ne 0) { Write-Error "git fetch upstream 失败:`n$($fetch.Output)"; exit 1 }

$behind = Invoke-Git @("log", "--oneline", "HEAD..upstream/main")
$behindLines = $behind.Output -split "`n" | Where-Object { $_.Trim() -ne "" }

if ($behindLines.Count -eq 0) {
    Write-Ext "已是最新，没有落后 upstream/main 的提交。"
    exit 0
}

Write-Ext "落后 upstream/main 共 $($behindLines.Count) 个提交："
$behindLines | ForEach-Object { Write-Host "    $_" }

if ($Check) { exit 0 }

$status = Invoke-Git @("status", "--porcelain")
$stashed = $false
if ($status.Output.Trim() -ne "") {
    $stash = Invoke-Git @("stash", "push", "-u", "-m", "fscan-ext-auto-stash")
    if ($stash.Code -ne 0) { Write-Error "git stash 失败:`n$($stash.Output)"; exit 1 }
    $stashed = $true
    Write-Ext "工作区有未提交修改，已自动 stash。"
}

function Restore-Stash {
    if ($stashed) {
        $pop = Invoke-Git @("stash", "pop")
        if ($pop.Code -ne 0) {
            Write-Warning "git stash pop 失败，改动仍保留在 stash 中，请手动执行 git stash list / git stash pop。`n$($pop.Output)"
        }
    }
}

$merge = Invoke-Git @("merge", "upstream/main", "--no-edit")
if ($merge.Code -ne 0) {
    Write-Error "合并发生冲突，已自动回滚，工作区保持干净：`n$($merge.Output)"
    Invoke-Git @("merge", "--abort") | Out-Null
    Restore-Stash
    exit 1
}
Write-Ext "已成功合并 upstream/main。"
Restore-Stash

Push-Location $RepoDir
try {
    & go mod download
    if ($LASTEXITCODE -ne 0) { Write-Error "go mod download 失败"; exit 1 }

    & go test -vet=off ./ext/...
    if ($LASTEXITCODE -ne 0) { Write-Error "扩展层测试未通过，已中止更新，本机 fscan.exe 未被改动。"; exit 1 }
    Write-Ext "扩展层测试通过。"

    $commitShort = (& git rev-parse --short HEAD).Trim()
    $buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $newBin = Join-Path $RepoDir "fscan.new.exe"
    $ldflags = "-s -w -X github.com/shadow1ng/fscan/common.commit=$commitShort -X github.com/shadow1ng/fscan/common.date=$buildDate"

    & go build -trimpath -ldflags $ldflags -o $newBin .
    if ($LASTEXITCODE -ne 0) { Write-Error "编译失败，本机 fscan.exe 未被改动。"; exit 1 }
    Write-Ext "编译完成: $newBin (commit $commitShort)"

    $oldBin = "$InstallBin.old"
    Remove-Item -Path $oldBin -ErrorAction SilentlyContinue
    if (Test-Path $InstallBin) {
        Rename-Item -Path $InstallBin -NewName (Split-Path $oldBin -Leaf) -ErrorAction Stop
    }
    Move-Item -Path $newBin -Destination $InstallBin -Force
    Write-Ext "已安全替换 $InstallBin，旧版本保留为 $InstallBin.old（下次启动 fscan 时自动清理）。"

    if ($Push) {
        & git push origin main
        if ($LASTEXITCODE -ne 0) { Write-Error "git push origin main 失败"; exit 1 }
        Write-Ext "已推送合并结果到 origin/main。"
    }
}
finally {
    Pop-Location
}
