package plugin

import (
	"fmt"
	"time"
)

// Plugin 插件接口
type Plugin interface {
	Name() string
	Description() string
	Scan(target string, port int, timeout time.Duration) (Result, error)
}

// Result 插件扫描结果
type Result struct {
	Vulnerable bool   `json:"vulnerable"`
	Details    string `json:"details"`
	Severity   string `json:"severity"` // low, medium, high, critical
}

// PluginManager 插件管理器
type PluginManager struct {
	plugins map[string]Plugin
}

// NewPluginManager 创建插件管理器
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make(map[string]Plugin),
	}
}

// RegisterPlugin 注册插件
func (pm *PluginManager) RegisterPlugin(plugin Plugin) {
	pm.plugins[plugin.Name()] = plugin
	fmt.Printf("✅ 插件已注册: %s - %s\n", plugin.Name(), plugin.Description())
}

// GetPlugin 获取插件
func (pm *PluginManager) GetPlugin(name string) (Plugin, bool) {
	plugin, exists := pm.plugins[name]
	return plugin, exists
}

// ListPlugins 列出所有插件
func (pm *PluginManager) ListPlugins() []string {
	var plugins []string
	for name := range pm.plugins {
		plugins = append(plugins, name)
	}
	return plugins
}
