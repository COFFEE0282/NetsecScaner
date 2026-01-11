package main

import (
	"fmt"
	"netscanner/internal/plugin"
	"netscanner/internal/reporter" // 添加reporter包导入
	"netscanner/internal/scanner"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	// 定义命令行参数变量
	var (
		host      string
		ports     string
		timeout   int
		workers   int
		pluginArg string // 改为pluginArg避免与包名冲突
		scanMode  string
		report    string // 添加报告文件参数
	)

	// 创建根命令
	rootCmd := &cobra.Command{
		Use:   "netscanner",
		Short: "网络端口扫描器",
		Long: `一个快速的TCP端口扫描器，支持IPv4/IPv6双栈
支持并发扫描、服务指纹识别、安全插件检测`,
		Run: func(cmd *cobra.Command, args []string) {
			// 初始化插件管理器
			pluginManager := initializePlugins()

			// 如果指定了插件，运行插件扫描模式
			if pluginArg != "" {
				runPluginScan(host, pluginArg, pluginManager, timeout)
				return
			}

			// 正常端口扫描模式
			runPortScan(host, ports, timeout, workers, scanMode, pluginManager, report)
		},
	}

	// 定义命令行标志
	rootCmd.Flags().StringVarP(&host, "host", "H", "localhost", "要扫描的主机名或IP地址")
	rootCmd.Flags().StringVarP(&ports, "ports", "p", "1-100", "端口范围，如：80,443 或 1-1000")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 2, "连接超时时间（秒）")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 100, "并发工作线程数")
	rootCmd.Flags().StringVarP(&pluginArg, "plugin", "P", "", "运行指定插件扫描")
	rootCmd.Flags().StringVarP(&scanMode, "mode", "m", "normal", "扫描模式: normal（普通）, security（安全扫描）")
	rootCmd.Flags().StringVarP(&report, "report", "r", "", "生成HTML报告文件")

	// 添加插件子命令
	pluginCmd := &cobra.Command{
		Use:   "plugins",
		Short: "管理插件",
		Run: func(cmd *cobra.Command, args []string) {
			pluginManager := initializePlugins()
			listPlugins(pluginManager)
		},
	}
	rootCmd.AddCommand(pluginCmd)

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("错误:", err)
	}
}

// initializePlugins 初始化插件系统
func initializePlugins() *plugin.PluginManager {
	pm := plugin.NewPluginManager()

	// 注册插件
	pm.RegisterPlugin(&plugin.FTPWeakPassPlugin{})
	pm.RegisterPlugin(&plugin.HTTPSecurityPlugin{})

	return pm
}

// listPlugins 列出所有插件
func listPlugins(pm *plugin.PluginManager) {
	fmt.Println("📦 可用插件：")
	for _, name := range pm.ListPlugins() {
		if p, exists := pm.GetPlugin(name); exists {
			fmt.Printf("  • %s: %s\n", p.Name(), p.Description())
		}
	}
}

// runPluginScan 运行插件扫描
func runPluginScan(host, pluginName string, pm *plugin.PluginManager, timeout int) {
	p, exists := pm.GetPlugin(pluginName)
	if !exists {
		fmt.Printf("❌ 插件不存在: %s\n", pluginName)
		fmt.Println("使用 'netscanner plugins' 查看可用插件")
		return
	}

	// 根据插件类型确定默认端口
	defaultPort := 21 // FTP
	if pluginName == "http-security" {
		defaultPort = 80
	}

	fmt.Printf("🔍 使用插件 %s 扫描 %s:%d\n", pluginName, host, defaultPort)

	result, err := p.Scan(host, defaultPort, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Printf("❌ 扫描失败: %v\n", err)
		return
	}

	fmt.Println("📊 扫描结果：")
	if result.Vulnerable {
		fmt.Printf("  状态: 🔴 存在风险\n")
		fmt.Printf("  详情: %s\n", result.Details)
		fmt.Printf("  等级: %s\n", result.Severity)
	} else {
		fmt.Printf("  状态: 🟢 安全\n")
		fmt.Printf("  详情: %s\n", result.Details)
	}
}

// runPortScan 运行端口扫描
func runPortScan(host, ports string, timeout, workers int, scanMode string, pm *plugin.PluginManager, report string) {
	// 解析端口范围
	portList := parsePorts(ports)
	if len(portList) == 0 {
		fmt.Println("❌ 错误：没有有效的端口可扫描")
		return
	}

	// 清理主机地址
	host = normalizeHost(host)

	// 显示扫描信息
	fmt.Printf("🚀 开始扫描 %s 的 %d 个端口...\n", host, len(portList))
	fmt.Printf("  模式: %s, 超时: %ds, 并发数: %d\n\n", scanMode, timeout, workers)

	// 创建扫描器
	tcpScanner := scanner.NewTCPScanner(time.Duration(timeout)*time.Second, workers)

	start := time.Now()
	results := tcpScanner.ScanPorts(host, portList)
	elapsed := time.Since(start)

	// 显示结果
	displayResults(results, scanMode, pm, host, timeout)

	// 生成HTML报告
	if report != "" {
		generateHTMLReport(host, start, time.Now(), results, report)
	}

	fmt.Printf("\n✅ 扫描完成！耗时: %v\n", elapsed)
}

// normalizeHost 规范化主机地址
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.Trim(host, "[]")
	}
	return host
}

// parsePorts 解析端口字符串
func parsePorts(portStr string) []int {
	var ports []int
	portMap := make(map[int]bool) // 使用map去重

	// 分割逗号分隔的部分
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 判断是否是范围
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))

				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					for port := start; port <= end; port++ {
						if port > 0 && port <= 65535 {
							portMap[port] = true
						}
					}
				}
			}
		} else {
			// 单个端口
			if port, err := strconv.Atoi(part); err == nil && port > 0 && port <= 65535 {
				portMap[port] = true
			}
		}
	}

	// 将map转换为切片
	for port := range portMap {
		ports = append(ports, port)
	}

	// 排序（可选，便于阅读）
	sort.Ints(ports)

	return ports
}

// displayResults 显示扫描结果
func displayResults(results []scanner.ScanResult, scanMode string, pm *plugin.PluginManager, host string, timeout int) {
	openCount := 0
	ipv6Count := 0

	fmt.Println("端口\t状态\t服务\t\tIP版本\tBanner")
	fmt.Println("----\t----\t----\t\t------\t------")

	for _, result := range results {
		if result.State == "open" {
			openCount++
			if result.IPVersion == "IPv6" {
				ipv6Count++
			}

			// 截断过长的banner
			banner := result.Banner
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}

			fmt.Printf("%d\t%s\t%s\t\t%s\t%s\n",
				result.Port, result.State, result.Service, result.IPVersion, banner)

			// 如果是安全扫描模式，运行相关插件
			if scanMode == "security" {
				runSecurityPlugins(pm, host, result.Port, result.Service, timeout)
			}
		}
	}

	fmt.Printf("\n📊 统计信息：\n")
	fmt.Printf("  总端口数: %d\n", len(results))
	fmt.Printf("  开放端口: %d\n", openCount)
	fmt.Printf("  关闭端口: %d\n", len(results)-openCount)
	if ipv6Count > 0 {
		fmt.Printf("  IPv6端口: %d ✅\n", ipv6Count)
	}
}

// runSecurityPlugins 运行安全插件
func runSecurityPlugins(pm *plugin.PluginManager, host string, port int, service string, timeout int) {
	// 根据服务类型选择插件
	var pluginName string
	switch service {
	case "ftp":
		pluginName = "ftp-weakpass"
	case "http", "https":
		pluginName = "http-security"
	default:
		return
	}

	if p, exists := pm.GetPlugin(pluginName); exists {
		fmt.Printf("  🔍 对 %s:%d 运行 %s 检查...\n", host, port, pluginName)

		result, err := p.Scan(host, port, time.Duration(timeout)*time.Second)
		if err == nil {
			if result.Vulnerable {
				fmt.Printf("    ⚠️ 风险等级: %s\n", result.Severity)
				fmt.Printf("    📝 详情: %s\n", limitString(result.Details, 60))
			} else {
				fmt.Printf("    ✓ %s\n", result.Details)
			}
		} else {
			fmt.Printf("    ⚠️ 检查失败: %v\n", err)
		}
	}
}

// limitString 限制字符串长度
func limitString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// generateHTMLReport 生成HTML报告
func generateHTMLReport(host string, startTime, endTime time.Time, results []scanner.ScanResult, reportFile string) {
	// 统计信息
	openCount := 0
	ipv6Count := 0
	var openResults []scanner.ScanResult

	for _, result := range results {
		if result.State == "open" {
			openCount++
			openResults = append(openResults, result)
			if result.IPVersion == "IPv6" {
				ipv6Count++
			}
		}
	}

	// 准备报告数据
	report := reporter.ScanReport{
		Target:      host,
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    endTime.Sub(startTime),
		TotalPorts:  len(results),
		OpenPorts:   openCount,
		ClosedPorts: len(results) - openCount,
		IPv6Ports:   ipv6Count,
		HasIPv6:     ipv6Count > 0,
	}

	// 转换结果格式
	for _, r := range openResults {
		report.Results = append(report.Results, reporter.ScanResult{
			Port:      r.Port,
			State:     r.State,
			Service:   r.Service,
			Banner:    r.Banner,
			IPVersion: r.IPVersion,
		})
	}

	// 生成报告
	err := reporter.GenerateHTMLReport(report, reportFile)
	if err != nil {
		fmt.Printf("❌ 生成报告失败: %v\n", err)
	} else {
		fmt.Printf("📄 HTML报告已生成: %s\n", reportFile)
	}
}
