//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installService() {
	// 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)

	// 生成服务文件内容
	serviceContent := fmt.Sprintf(`[Unit]
Description=netZero VPN Service
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

	// 保存服务文件
	servicePath := "./netzero.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("保存服务文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("服务文件已生成: netzero.service")
	fmt.Println("\n请检查之前是否注册过服务:")
	fmt.Println("  sudo systemctl status netzero.service")
	fmt.Println("\n安装指令:")
	fmt.Println("  # 复制服务文件到systemd目录")
	fmt.Println("  sudo cp netzero.service /etc/systemd/system/")
	fmt.Println("")
	fmt.Println("  # 重新加载 systemd 配置")
	fmt.Println("  sudo systemctl daemon-reload")
	fmt.Println("")
	fmt.Println("  # 设置开机自启")
	fmt.Println("  sudo systemctl enable --now netzero.service")
	fmt.Println("")
	fmt.Println("  # 查看状态")
	fmt.Println("  sudo systemctl status netzero.service")
	fmt.Println("")
	fmt.Println("  # 查看日志")
	fmt.Println("  sudo journalctl -u netzero.service -f")
}

func startNebula() {
	configPath := "./config/config.yml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("配置文件不存在: %s\n", configPath)
		os.Exit(1)
	}

	var cmd *exec.Cmd

	cmd = exec.Command("sudo", "./nebula", "-config", configPath)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("执行命令: %s\n", strings.Join(cmd.Args, " "))

	if err := cmd.Start(); err != nil {
		fmt.Printf("启动nebula失败: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		fmt.Printf("nebula进程异常退出: %v\n", err)
		os.Exit(1)
	}
}
