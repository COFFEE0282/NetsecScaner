package plugin

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPSecurityPlugin HTTP安全检测插件
type HTTPSecurityPlugin struct{}

// Name 插件名称
func (p *HTTPSecurityPlugin) Name() string {
	return "http-security"
}

// Description 插件描述
func (p *HTTPSecurityPlugin) Description() string {
	return "检测HTTP服务的安全头信息"
}

// Scan 执行扫描
func (p *HTTPSecurityPlugin) Scan(target string, port int, timeout time.Duration) (Result, error) {
	url := fmt.Sprintf("http://%s:%d", target, port)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return Result{Vulnerable: false}, err
	}
	defer resp.Body.Close()

	// 检查安全头
	missingHeaders := []string{}
	recommendations := []string{}

	securityHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expectedValue := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			missingHeaders = append(missingHeaders, header)
			recommendations = append(recommendations,
				fmt.Sprintf("建议添加 %s 头，期望值: %s", header, expectedValue))
		} else if header == "X-Frame-Options" &&
			strings.ToUpper(value) != "DENY" &&
			!strings.Contains(strings.ToUpper(value), "SAMEORIGIN") {
			recommendations = append(recommendations,
				fmt.Sprintf("%s 头配置不安全: %s (期望: %s)", header, value, expectedValue))
		}
		// 注意：这里我们使用了 expectedValue 变量，修复了编译错误
	}

	if len(missingHeaders) > 0 {
		return Result{
			Vulnerable: true,
			Details:    fmt.Sprintf("缺少安全头: %v。建议: %v", missingHeaders, recommendations),
			Severity:   "low",
		}, nil
	}

	if len(recommendations) > 0 {
		return Result{
			Vulnerable: true,
			Details:    fmt.Sprintf("安全头配置需要改进: %v", recommendations),
			Severity:   "low",
		}, nil
	}

	return Result{
		Vulnerable: false,
		Details:    "基本安全头已正确配置",
	}, nil
}
