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
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)

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
StartLimitInterval=100s
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
`, exeDir, filepath.Join(exeDir, exeName))

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

func checkAndCleanService() {
	cmd := exec.Command("systemctl", "status", "netzero.service")
	if err := cmd.Run(); err == nil {
		fmt.Println("检测到 netzero.service 正在运行，正在自动停止并删除...")

		// 停止并禁用服务
		cmd = exec.Command("systemctl", "disable", "--now", "netzero.service")
		if err := cmd.Run(); err != nil {
			fmt.Printf("停止服务失败: %v\n", err)
		} else {
			fmt.Println("服务已停止并禁用")
		}

		// 删除systemd服务文件
		cmd = exec.Command("rm", "-f", "/etc/systemd/system/netzero.service")
		if err := cmd.Run(); err != nil {
			fmt.Printf("删除服务文件失败: %v\n", err)
		} else {
			fmt.Println("已删除 /etc/systemd/system/netzero.service")
		}

		// 重新加载systemd配置
		cmd = exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			fmt.Printf("重新加载systemd配置失败: %v\n", err)
		} else {
			fmt.Println("已重新加载systemd配置")
		}
	}

	// 删除当前目录下的服务文件
	if err := os.Remove("./netzero.service"); err == nil {
		fmt.Println("已删除 ./netzero.service")
	} else if !os.IsNotExist(err) {
		fmt.Printf("删除 ./netzero.service 失败: %v\n", err)
	}
}
