package reporter

import (
	"fmt"
	"html/template"
	"net"
	"os"
	"time"
)

// ScanReport 扫描报告
type ScanReport struct {
	Target      string
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	TotalPorts  int
	OpenPorts   int
	ClosedPorts int
	IPv6Ports   int
	Results     []ScanResult
	HasIPv6     bool
}

// ScanResult 扫描结果
type ScanResult struct {
	Port      int
	State     string
	Service   string
	Banner    string
	IPVersion string
}

// GenerateHTMLReport 生成HTML报告
func GenerateHTMLReport(report ScanReport, outputFile string) error {
	// HTML模板
	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络扫描报告 - {{.Target}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card.total { border-top: 4px solid #3498db; }
        .card.open { border-top: 4px solid #2ecc71; }
        .card.closed { border-top: 4px solid #e74c3c; }
        .card.ipv6 { border-top: 4px solid #9b59b6; }
        
        .card h3 {
            font-size: 14px;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .card .number {
            font-size: 36px;
            font-weight: bold;
        }
        
        .scan-results {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        
        .scan-results h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #eee;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .status-open {
            display: inline-block;
            padding: 4px 8px;
            background: #2ecc71;
            color: white;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .status-closed {
            display: inline-block;
            padding: 4px 8px;
            background: #e74c3c;
            color: white;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .ipv6-badge {
            display: inline-block;
            padding: 2px 6px;
            background: #9b59b6;
            color: white;
            border-radius: 3px;
            font-size: 10px;
            margin-left: 5px;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            color: white;
            font-size: 14px;
        }
        
        .footer a {
            color: white;
            text-decoration: underline;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 10px;
        }
        
        .highlight {
            background: #fffacd;
            padding: 2px 4px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 网络端口扫描报告</h1>
            <p class="timestamp">
                目标: <span class="highlight">{{.Target}}</span> |
                开始时间: {{.StartTime.Format "2006-01-02 15:04:05"}} |
                结束时间: {{.EndTime.Format "2006-01-02 15:04:05"}} |
                耗时: {{printf "%.2f" .Duration.Seconds}}秒
            </p>
        </div>
        
        <div class="summary-cards">
            <div class="card total">
                <h3>总端口数</h3>
                <div class="number">{{.TotalPorts}}</div>
            </div>
            
            <div class="card open">
                <h3>开放端口</h3>
                <div class="number">{{.OpenPorts}}</div>
            </div>
            
            <div class="card closed">
                <h3>关闭端口</h3>
                <div class="number">{{.ClosedPorts}}</div>
            </div>
            
            {{if .HasIPv6}}
            <div class="card ipv6">
                <h3>IPv6端口</h3>
                <div class="number">{{.IPv6Ports}}</div>
                <small>✅ IPv6支持已启用</small>
            </div>
            {{end}}
        </div>
        
        <div class="scan-results">
            <h2>📋 扫描结果详情</h2>
            
            {{if .Results}}
            <table>
                <thead>
                    <tr>
                        <th>端口</th>
                        <th>状态</th>
                        <th>服务</th>
                        <th>IP版本</th>
                        <th>Banner信息</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Results}}
                    <tr>
                        <td><strong>{{.Port}}</strong></td>
                        <td>
                            {{if eq .State "open"}}
                            <span class="status-open">开放</span>
                            {{else}}
                            <span class="status-closed">关闭</span>
                            {{end}}
                        </td>
                        <td>{{.Service}}</td>
                        <td>
                            {{.IPVersion}}
                            {{if eq .IPVersion "IPv6"}}
                            <span class="ipv6-badge">IPv6</span>
                            {{end}}
                        </td>
                        <td><code>{{.Banner}}</code></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <p style="text-align: center; color: #7f8c8d; padding: 40px;">
                没有找到开放端口
            </p>
            {{end}}
        </div>
        
        <div class="footer">
            <p>报告由 <strong>NetSecScanner</strong> 生成 | {{.EndTime.Format "2006-01-02"}}</p>
            <p>仅供安全测试和教育目的使用</p>
        </div>
    </div>
</body>
</html>`

	// 创建模板
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析模板失败: %v", err)
	}

	// 创建输出文件
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 执行模板
	err = tmpl.Execute(file, report)
	if err != nil {
		return fmt.Errorf("生成报告失败: %v", err)
	}

	return nil
}

// IsIPv6 判断是否为IPv6地址
func IsIPv6(address string) bool {
	// 尝试解析地址
	if ip := net.ParseIP(address); ip != nil {
		return ip.To4() == nil
	}
	return false
}
