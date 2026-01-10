package main

import (
	"fmt"
	"netscanner/internal/scanner"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	// 定义命令行参数变量
	var (
		host    string //网址url
		ports   string //端口号
		timeout int    //用来自主设定超时时间
		workers int    //用来自主设定并发的线程数
	)

	// 创建根命令
	rootCmd := &cobra.Command{
		Use:   "netscanner",
		Short: "网络端口扫描器",
		Long:  "一个快速的TCP端口扫描器，支持并发扫描和常见服务识别",
		Run: func(cmd *cobra.Command, args []string) {
			// 解析端口范围
			portList := parsePorts(ports)
			if len(portList) == 0 {
				fmt.Println("错误：没有有效的端口可扫描")
				return
			}

			// 创建扫描器
			tcpScanner := scanner.NewTCPScanner(time.Duration(timeout)*time.Second, workers)

			fmt.Printf("开始扫描 %s 的 %d 个端口...\n\n", host, len(portList))

			start := time.Now()
			results := tcpScanner.ScanPorts(host, portList)
			elapsed := time.Since(start)

			// 显示结果
			displayResults(results)

			fmt.Printf("\n扫描完成！耗时: %v\n", elapsed)
		},
	}

	// 定义命令行标志
	rootCmd.Flags().StringVarP(&host, "host", "H", "localhost", "要扫描的主机名或IP地址")
	rootCmd.Flags().StringVarP(&ports, "ports", "p", "1-100", "端口范围，如：80,443 或 1-1000")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 2, "连接超时时间（秒）")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 100, "并发工作线程数")

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("错误:", err)
	}
}

// parsePorts 解析端口字符串
func parsePorts(portStr string) []int {
	var ports []int

	// 处理逗号分隔的端口列表
	if strings.Contains(portStr, ",") {
		parts := strings.Split(portStr, ",")
		for _, part := range parts {
			if port, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				ports = append(ports, port)
			}
		}
		return ports
	}

	// 处理端口范围（如 1-100）
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

			if err1 == nil && err2 == nil && start <= end {
				for port := start; port <= end; port++ {
					ports = append(ports, port)
				}
			}
		}
		return ports
	}

	// 单个端口
	if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
		ports = append(ports, port)
	}

	return ports
}

// displayResults 将扫描结果输出至终端
func displayResults(results []scanner.ScanResult) {
	openCount := 0

	fmt.Println("端口\t状态\t服务")
	fmt.Println("----\t----\t----")

	for _, result := range results {
		if result.State == "open" {
			fmt.Printf("%d\t%s\t%s\n", result.Port, result.State, result.Service)
			openCount++
		} else {
			// 只显示开放端口，关闭端口太多，显示会很长
			// fmt.Printf("%d\t%s\n", result.Port, result.State)
		}
	}

	fmt.Printf("\n总端口数: %d\n", len(results))
	fmt.Printf("开放端口: %d\n", openCount)
	fmt.Printf("关闭端口: %d\n", len(results)-openCount)
}
