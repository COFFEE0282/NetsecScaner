package plugin

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// FTPWeakPassPlugin FTP弱口令检测插件
type FTPWeakPassPlugin struct{}

// Name 插件名称
func (p *FTPWeakPassPlugin) Name() string {
	return "ftp-weakpass"
}

// Description 插件描述
func (p *FTPWeakPassPlugin) Description() string {
	return "检测FTP服务的弱口令"
}

// Scan 执行扫描
func (p *FTPWeakPassPlugin) Scan(target string, port int, timeout time.Duration) (Result, error) {
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Result{Vulnerable: false}, err
	}
	defer conn.Close()

	// 读取banner
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return Result{Vulnerable: false}, err
	}

	banner := string(buffer[:n])
	if !strings.Contains(strings.ToLower(banner), "ftp") {
		return Result{Vulnerable: false}, fmt.Errorf("不是FTP服务")
	}

	// 测试常见弱口令
	weakPasswords := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "123456"},
		{"admin", "password"},
		{"root", "root"},
		{"root", "123456"},
		{"ftp", "ftp"},
		{"anonymous", ""}, // 匿名登录
		{"anonymous", "anonymous"},
	}

	for _, cred := range weakPasswords {
		if p.testFTPLogin(conn, cred.username, cred.password, timeout) {
			return Result{
				Vulnerable: true,
				Details:    fmt.Sprintf("发现弱口令: %s/%s", cred.username, cred.password),
				Severity:   "medium",
			}, nil
		}
	}

	return Result{Vulnerable: false, Details: "未发现常见弱口令"}, nil
}

// testFTPLogin 测试FTP登录
func (p *FTPWeakPassPlugin) testFTPLogin(conn net.Conn, username, password string, timeout time.Duration) bool {
	// 发送用户名
	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(fmt.Sprintf("USER %s\r\n", username)))

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:n]), "331") {
		return false
	}

	// 发送密码
	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", password)))

	// 读取登录响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err = conn.Read(buffer)
	if err != nil {
		return false
	}

	response := string(buffer[:n])
	return strings.HasPrefix(response, "230")
}
