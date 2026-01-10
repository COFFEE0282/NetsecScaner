package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanResult 存储扫描结果
type ScanResult struct {
	Port    int
	State   string
	Service string
}

// TCPScanner TCP扫描器
type TCPScanner struct {
	Timeout    time.Duration
	MaxWorkers int
}

// 实现tcp扫描器的初始化
func NewTCPScanner(timeout time.Duration, maxWorkers int) *TCPScanner {
	return &TCPScanner{
		Timeout:    timeout,
		MaxWorkers: maxWorkers,
	}
}

// ScanPort 扫描单个端口，为后面并发地扫描多个端口提供函数
func (s *TCPScanner) ScanPort(host string, port int) ScanResult {
	address := fmt.Sprintf("%s:%d", host, port)
	connect, err := net.DialTimeout("tcp", address, s.Timeout)

	// 初始化结果
	result := ScanResult{
		Port:    port,
		State:   "closed",
		Service: "unknown",
	}

	if err == nil {
		connect.Close()
		result.State = "open"
		// 这里可以添加服务识别逻辑
		result.Service = s.guessService(port)
	}

	return result
}

// guessService 设置判断服务的函数
func (s *TCPScanner) guessService(port int) string {
	// 常见的端口与服务映射
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		443:  "https",
		3306: "mysql",
		3389: "rdp",
		8080: "http-proxy",
	}

	if service, ok := serviceMap[port]; ok {
		return service
	}
	return "unknown"
}

// ScanPorts 并发扫描多个端口
func (s *TCPScanner) ScanPorts(host string, ports []int) []ScanResult {
	var results []ScanResult
	var mu sync.Mutex // 保护results的并发访问
	var wg sync.WaitGroup

	// 创建worker池
	jobs := make(chan int, s.MaxWorkers)

	// 启动worker
	for i := 0; i < s.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				result := s.ScanPort(host, port)

				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	// 分发任务
	for _, port := range ports {
		jobs <- port
	}
	close(jobs)

	// 等待所有worker完成
	wg.Wait()

	return results
}
