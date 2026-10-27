// Package ext 是 fscan 的零侵入式扩展包：合规速查手册、安全场景预设、交互向导与自更新。
//
// 范围声明（重要）：本扩展包仅覆盖资产测绘（scan）、输入输出（io）、代理与限速（net）、
// 本地主机基线自检（host-audit）四个领域。弱口令字典管理（-user/-pwd/-userf/-pwdf/-upf/
// -hash/-sshkey）、漏洞 POC 验证与利用（-full/-pocpath/-pocname/-dns/-rf/-rs/-rwp/-rwc/-rwf）、
// 以及"未授权访问探测"类场景预设，均不在本扩展包的封装范围内——这类能力本身存在于上游 fscan
// 原生参数中，如确有授权测试需要，请直接使用原生参数，本扩展不提供任何向导、预设或字典封装。
package ext

import "strings"

// ComplianceBanner 在 guide 顶层输出中展示，说明扩展包的能力边界。
const ComplianceBanner = `本扩展仅覆盖「资产测绘 / 输入输出 / 代理限速 / 本地基线自检」四大合规场景；
不提供弱口令字典、漏洞POC验证或未授权访问探测类预设与向导封装。
如需授权范围内的深度安全测试，请直接使用 fscan 原生参数（本扩展不做任何改动或限制）。`

// Item 描述一个具体的合规审计场景
type Item struct {
	Name     string   // 场景名称
	Keywords []string // 中英文模糊检索关键词
	Note     string   // 合规提示 / 避坑说明
	Commands []string // 可直接复制的示例命令
}

// Category 描述一个能力域
type Category struct {
	Key     string // 分类标识，如 "scan"
	Title   string // 中文标题
	Summary string // 一句话描述
	Items   []Item
}

// Categories 是本扩展包内置的能力域知识库，所有命令均来自对上游 common/flag.go 的
// 真实参数核对（见 main_cli.go / plugins 包注册信息），严禁出现已废弃或虚构参数。
var Categories = []Category{
	{
		Key:     "scan",
		Title:   "资产测绘与网络可达性",
		Summary: "主机存活、端口开放性、服务识别与 Web 指纹识别——只读探测，不做凭据或漏洞验证",
		Items: []Item{
			{
				Name:     "主机存活探测",
				Keywords: []string{"存活", "ping", "icmp", "alive", "段扫描", "B段", "C段"},
				Note:     "大网段建议先用 -ao 摸底存活，再对存活主机做精确端口扫描，避免无效端口扫描占满线程。",
				Commands: []string{
					"fscan -h 192.168.1.0/24 -ao -nobr -nopoc            # 仅存活探测，不扫端口",
					"fscan -h 192.168.1.0/24 -np -nobr -nopoc            # 跳过ICMP，仅凭TCP判断存活",
					"fscan -h 192.168.1.0/24 -ntp -nobr -nopoc           # 禁用TCP补充探测，仅信ICMP",
					"fscan -h 192.168.1.0/24 -nsp -nobr -nopoc           # 禁用子网抽样存活探测，逐IP探测",
				},
			},
			{
				Name:     "端口开放性探测",
				Keywords: []string{"端口", "port", "范围", "分组", "web", "db", "service"},
				Note:     "端口组(web/db/service/all)会自动并入对应协议常用端口集合，无需手工枚举。",
				Commands: []string{
					"fscan -h 192.168.1.10 -p 22,80,443,445,3306 -nobr -nopoc",
					"fscan -h 192.168.1.10 -p 1-65535 -t 800 -nobr -nopoc      # 全端口范围",
					"fscan -h 192.168.1.10 -p web -nobr -nopoc                 # 端口组：web|db|service|all",
					"fscan -h 192.168.1.10 -p 1-1000 -ep 25,110 -nobr -nopoc   # 排除端口",
				},
			},
			{
				Name:     "服务识别与插件调用",
				Keywords: []string{"服务识别", "插件", "-m", "list-plugins", "模块"},
				Note:     "-m 指定的模块若带固定端口且未传 -p/-pf，会自动采用该模块注册的默认端口集合；具体端口以 -list-plugins 的实时输出为准。",
				Commands: []string{
					"fscan -h 192.168.1.10 -m ssh,smb,mysql -nobr -nopoc       # 仅识别指定服务，不做凭据核验",
					"fscan -list-plugins                                       # 查看当前构建可用模块、类型与默认端口",
				},
			},
			{
				Name:     "Web资产指纹识别",
				Keywords: []string{"web", "指纹", "标题", "webtitle", "cms"},
				Note:     "仅做标题/中间件/CMS指纹识别，不加载漏洞POC——本扩展不封装 -full/-pocpath 等POC验证参数。",
				Commands: []string{
					"fscan -u http://192.168.1.10 -m webtitle -nobr -nopoc",
					"fscan -uf urls.txt -m webtitle -cookie \"a=1\" -ua \"Mozilla/5.0\" -wt 5 -max-redirect 5 -nobr -nopoc",
				},
			},
		},
	},
	{
		Key:     "io",
		Title:   "输入输出与结构化审计报告",
		Summary: "目标批量导入、排除规则、多格式报告与静默 NDJSON 管道",
		Items: []Item{
			{
				Name:     "审计目标输入与排除",
				Keywords: []string{"目标", "hf", "pf", "排除", "eh", "ehf", "cidr"},
				Note:     "-eh/-ehf 用于排除明确不在授权范围内的主机，建议在任何批量测绘前核对排除清单。",
				Commands: []string{
					"fscan -hf targets.txt -nobr -nopoc",
					"fscan -h 192.168.1.0/24 -eh 192.168.1.1 -nobr -nopoc",
					"fscan -h 192.168.1.0/24 -ehf exclude.txt -nobr -nopoc",
				},
			},
			{
				Name:     "多格式审计报告",
				Keywords: []string{"输出", "报告", "json", "csv", "txt", "-o", "-f"},
				Note:     "-no 仅屏幕输出不落盘，适合临时排查；正式审计建议落盘 json 便于归档与二次处理。",
				Commands: []string{
					"fscan -h 192.168.1.10 -o audit_result.json -f json -nobr -nopoc",
					"fscan -h 192.168.1.10 -o audit_result.csv -f csv -nobr -nopoc",
					"fscan -h 192.168.1.10 -no -nobr -nopoc              # 仅屏幕输出，不落盘",
				},
			},
			{
				Name:     "静默管道与SIEM/Agent联动",
				Keywords: []string{"silent", "静默", "ndjson", "siem", "agent", "jq", "debug", "perf"},
				Note:     "⚠ -silent 模式下 stdout 只允许出现原生 NDJSON；本扩展任何提示信息一律写 stderr，绝不污染 stdout。",
				Commands: []string{
					"fscan -h 192.168.1.0/24 -silent -nobr -nopoc | jq 'select(.type==\"PORT\")'",
					"fscan -h 192.168.1.10 -debug -nobr -nopoc           # NDJSON走stdout，调试日志写入 fscan_debug.log",
					"fscan -h 192.168.1.10 -perf -nobr -nopoc            # 输出JSON格式性能统计",
				},
			},
		},
	},
	{
		Key:     "net",
		Title:   "安全审计代理与限速防影响",
		Summary: "SOCKS5/HTTP代理穿透扫描、网卡绑定与业务友好型发包速率控制",
		Items: []Item{
			{
				Name:     "代理穿透审计扫描",
				Keywords: []string{"代理", "proxy", "socks5", "vpn", "iface", "网卡"},
				Note:     "⚠ 挂 SOCKS5 代理扫描内网时必须搭配 -np 跳过ICMP，否则代理链路不转发ICMP会导致目标被误判为不存活！",
				Commands: []string{
					"fscan -h 10.0.0.0/24 -socks5 127.0.0.1:1080 -np -nobr -nopoc",
					"fscan -u http://target -proxy http://127.0.0.1:8080 -nobr -nopoc",
					"fscan -h 10.0.0.0/24 -iface 10.8.0.2 -nobr -nopoc      # VPN场景绑定出口网卡",
				},
			},
			{
				Name:     "速率与并发控制",
				Keywords: []string{"限速", "rate", "线程", "超时", "icmp-rate", "并发"},
				Note:     "生产网络审计建议显式限制线程数与发包速率，避免对业务链路造成拥塞影响。",
				Commands: []string{
					"fscan -h 192.168.1.0/24 -t 100 -rate 200 -nobr -nopoc        # 限速保护生产网络",
					"fscan -h 192.168.1.0/24 -mt 10 -time 5 -gt 600 -nobr -nopoc  # 模块线程/超时/全局超时",
					"fscan -h 192.168.1.0/24 -icmp-rate 0.05 -nobr -nopoc         # 降低ICMP令牌桶速率",
				},
			},
		},
	},
	{
		Key:     "host-audit",
		Title:   "本地主机安全基线自检",
		Summary: "仅针对运行 fscan 的本机做自检，不连接任何远程目标",
		Items: []Item{
			{
				Name:     "系统环境信息自检",
				Keywords: []string{"systeminfo", "系统信息", "本机", "环境"},
				Note:     "收集本机系统/硬件/环境信息，纯本地读取，不发出任何网络探测包。",
				Commands: []string{"fscan -local systeminfo"},
			},
			{
				Name:     "Windows计划任务基线",
				Keywords: []string{"winschtask", "计划任务", "schtask"},
				Note:     "核查本机已注册的计划任务配置，用于基线比对，不做任何写入操作。",
				Commands: []string{"fscan -local winschtask"},
			},
			{
				Name:     "Windows服务基线",
				Keywords: []string{"winservice", "服务", "service"},
				Note:     "核查本机已安装的 Windows 服务配置基线。",
				Commands: []string{"fscan -local winservice"},
			},
			{
				Name:     "Linux定时任务基线",
				Keywords: []string{"crontask", "cron", "定时任务", "linux"},
				Note:     "核查本机 crontab/定时任务配置基线（Linux/macOS 主机）。",
				Commands: []string{"fscan -local crontask"},
			},
			{
				Name:     "本地SOCKS5代理连通性自检",
				Keywords: []string{"socks5proxy", "代理自检", "start-socks5", "连通性"},
				Note:     "在本机启动一个 SOCKS5 代理服务用于审计链路连通性自测，不代理发起对外攻击。",
				Commands: []string{"fscan -local socks5proxy -start-socks5 1080"},
			},
		},
	},
	{
		Key:     "ext",
		Title:   "扩展向导与自动维护",
		Summary: "guide / examples / preset / wizard / update 的完整用法",
		Items: []Item{
			{
				Name:     "速查手册",
				Keywords: []string{"guide", "手册", "速查"},
				Note:     "fscan guide 查看全部分类；fscan guide <分类名|关键词> 查看详情或模糊检索。",
				Commands: []string{"fscan guide", "fscan guide scan", "fscan guide 代理"},
			},
			{
				Name:     "模块示例",
				Keywords: []string{"examples", "示例", "模块"},
				Note:     "fscan examples <模块名> 查看该服务/本地插件的合规排查命令集。",
				Commands: []string{"fscan examples smb", "fscan examples local"},
			},
			{
				Name:     "一键场景预设",
				Keywords: []string{"preset", "预设", "场景"},
				Note:     "fscan preset 查看全部预设；fscan preset <名称> [目标与追加参数] [--dry-run]。",
				Commands: []string{"fscan preset", "fscan preset stealth -h 127.0.0.1 --dry-run"},
			},
			{
				Name:     "交互式向导",
				Keywords: []string{"wizard", "向导", "ui"},
				Note:     "零命令记忆的分步终端向导，别名 -ui。",
				Commands: []string{"fscan wizard", "fscan -ui"},
			},
			{
				Name:     "自动合并更新",
				Keywords: []string{"update", "更新", "同步", "upstream"},
				Note:     "fscan update --check 仅检查；fscan update 执行合并编译热替换；--push 同步推送到个人仓库。",
				Commands: []string{"fscan update --check", "fscan update", "fscan update --push"},
			},
		},
	},
}

// CategoryByKey 按 key 精确查找分类
func CategoryByKey(key string) *Category {
	for i := range Categories {
		if Categories[i].Key == key {
			return &Categories[i]
		}
	}
	return nil
}

// matchResult 是一次模糊检索命中的分类+场景
type matchResult struct {
	Category *Category
	Item     *Item
}

// SearchCatalog 在全部分类的 Name/Keywords/Note/Commands 中做大小写无关的子串模糊检索
func SearchCatalog(query string) []matchResult {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var results []matchResult
	for ci := range Categories {
		cat := &Categories[ci]
		for ii := range cat.Items {
			item := &cat.Items[ii]
			if itemMatches(item, q) {
				results = append(results, matchResult{Category: cat, Item: item})
			}
		}
	}
	return results
}

func itemMatches(item *Item, q string) bool {
	if strings.Contains(strings.ToLower(item.Name), q) {
		return true
	}
	for _, kw := range item.Keywords {
		if strings.Contains(strings.ToLower(kw), q) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(item.Note), q) {
		return true
	}
	for _, c := range item.Commands {
		if strings.Contains(strings.ToLower(c), q) {
			return true
		}
	}
	return false
}
