//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=netZero Lighthouse VPN Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s run
Restart=always
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
`, exeDir, filepath.Join(exeDir, exeName))

	servicePath := "./lighthouse.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("保存服务文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("服务文件已生成: lighthouse.service")
	fmt.Println("\n请检查之前是否注册过服务:")
	fmt.Println("  sudo systemctl status lighthouse.service")
	fmt.Println("\n安装指令:")
	fmt.Println("  # 复制服务文件到systemd目录")
	fmt.Println("  sudo cp lighthouse.service /etc/systemd/system/")
	fmt.Println("")
	fmt.Println("  # 重新加载 systemd 配置")
	fmt.Println("  sudo systemctl daemon-reload")
	fmt.Println("")
	fmt.Println("  # 设置开机自启")
	fmt.Println("  sudo systemctl enable --now lighthouse.service")
	fmt.Println("")
	fmt.Println("  # 查看状态")
	fmt.Println("  sudo systemctl status lighthouse.service")
	fmt.Println("")
	fmt.Println("  # 查看日志")
	fmt.Println("  sudo journalctl -u lighthouse.service -f")
}
