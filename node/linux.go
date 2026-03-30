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
	// 保持向后兼容，调用新的自动安装函数
	installServiceAuto()
}

func installServiceAuto() {
	serviceName := "netzero.service"

	// 检查systemd是否可用
	if !checkSystemdAvailable() {
		fmt.Println("错误: systemd不可用，netZero服务只能在支持systemd的Linux系统上运行")
		os.Exit(1)
	}

	// 检查服务是否已存在
	if checkServiceExists(serviceName) {
		fmt.Println("netZero服务已存在")
		printServiceCommands(serviceName)
		return
	}

	// 自动安装服务
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

	// 生成服务文件
	servicePath := "./" + serviceName
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("保存服务文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("服务文件已生成: %s\n", serviceName)

	// 自动执行安装命令
	fmt.Println("\n正在自动安装服务...")

	// 复制服务文件到systemd目录
	cmd := exec.Command("sudo", "cp", servicePath, "/etc/systemd/system/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("执行: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("复制服务文件失败: %v\n", err)
		os.Exit(1)
	}

	// 重新加载systemd配置
	cmd = exec.Command("sudo", "systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("执行: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("重新加载systemd配置失败: %v\n", err)
		os.Exit(1)
	}

	// 启用并启动服务
	cmd = exec.Command("sudo", "systemctl", "enable", "--now", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("执行: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("启用服务失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n服务安装完成！\n")
	printServiceCommands(serviceName)
}

// 检查systemd是否可用
func checkSystemdAvailable() bool {
	cmd := exec.Command("systemctl", "--version")
	return cmd.Run() == nil
}

// 检查服务是否已存在
func checkServiceExists(serviceName string) bool {
	cmd := exec.Command("systemctl", "status", serviceName)
	return cmd.Run() == nil
}

// 打印服务管理命令
func printServiceCommands(serviceName string) {
	fmt.Println("\n服务管理命令:")
	fmt.Printf("  # 查看状态\n  sudo systemctl status %s\n", serviceName)
	fmt.Printf("  # 启动服务\n  sudo systemctl start %s\n", serviceName)
	fmt.Printf("  # 停止服务\n  sudo systemctl stop %s\n", serviceName)
	fmt.Printf("  # 重启服务\n  sudo systemctl restart %s\n", serviceName)
	fmt.Printf("  # 查看日志\n  sudo journalctl -u %s -f\n", serviceName)
	fmt.Printf("  # 禁用开机自启\n  sudo systemctl disable %s\n", serviceName)
	fmt.Printf("  # 删除服务 (需要先运行 'netZero redo')\n  sudo systemctl disable --now %s\n", serviceName)
	fmt.Printf("  sudo rm -f /etc/systemd/system/%s\n", serviceName)
	fmt.Printf("  sudo systemctl daemon-reload\n")
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
