package scanner

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult 存储扫描结果
type ScanResult struct {
	Port      int
	State     string
	Service   string
	Banner    string
	IPVersion string // 添加IP版本信息
}

// TCPScanner TCP扫描器
type TCPScanner struct {
	Timeout    time.Duration
	MaxWorkers int
}

// NewTCPScanner 创建新的TCP扫描器
func NewTCPScanner(timeout time.Duration, maxWorkers int) *TCPScanner {
	return &TCPScanner{
		Timeout:    timeout,
		MaxWorkers: maxWorkers,
	}
}

// ScanPort 扫描单个端口
func (s *TCPScanner) ScanPort(host string, port int) ScanResult {
	// 判断是否是IPv6地址
	ipVersion := "IPv4"
	if isIPv6(host) {
		ipVersion = "IPv6"
	}

	// 使用net.JoinHostPort自动处理IPv6地址
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, s.Timeout)

	result := ScanResult{
		Port:      port,
		State:     "closed",
		Service:   "unknown",
		IPVersion: ipVersion,
	}

	if err == nil {
		defer conn.Close()
		result.State = "open"

		// 尝试获取banner
		banner := s.getBanner(conn)
		if banner != "" {
			result.Banner = banner
		}

		// 根据端口和banner识别服务
		result.Service = s.identifyService(port, banner)
	}

	return result
}

// isIPv6 判断是否是IPv6地址
func isIPv6(host string) bool {
	// 去掉可能的方括号
	host = strings.Trim(host, "[]")

	// 尝试解析为IP
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() == nil && ip.To16() != nil
	}
	return false
}

// getBanner 尝试获取服务banner
func (s *TCPScanner) getBanner(conn net.Conn) string {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 尝试读取banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(buffer[:n]))
}

// identifyService 识别服务
func (s *TCPScanner) identifyService(port int, banner string) string {
	// 优先根据banner识别
	if banner != "" {
		banner = strings.ToLower(banner)

		switch {
		case strings.Contains(banner, "ssh"):
			return "ssh"
		case strings.Contains(banner, "ftp"):
			return "ftp"
		case strings.Contains(banner, "smtp"):
			return "smtp"
		case strings.Contains(banner, "http"):
			return "http"
		case strings.Contains(banner, "mysql"):
			return "mysql"
		case strings.Contains(banner, "redis"):
			return "redis"
		}
	}

	// 如果没有banner，根据端口猜测
	serviceMap := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		465:   "smtps",
		587:   "smtp",
		993:   "imaps",
		995:   "pop3s",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := serviceMap[port]; ok {
		return service
	}
	return "unknown"
}

// ScanPorts 并发扫描多个端口
func (s *TCPScanner) ScanPorts(host string, ports []int) []ScanResult {
	var results []ScanResult
	var mu sync.Mutex
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
