//go:build windows
// +build windows

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
	serviceName := "netZero"

	// 检查nssm是否可用
	if !checkNSSMAvailable() {
		fmt.Println("NSSM (Non-Sucking Service Manager) 未安装")
		fmt.Println("请使用以下命令安装:")
		fmt.Println("  winget install NSSM.NSSM")
		fmt.Println("\n安装完成后重新运行 'netZero service'")
		return
	}

	// 检查服务是否已存在
	if checkServiceExistsWindows(serviceName) {
		fmt.Println("netZero服务已存在")
		printServiceCommandsWindows(serviceName)
		return
	}

	// 自动安装服务
	exePath := "nebula.exe"
	absPath, err := filepath.Abs(exePath)
	if err != nil {
		absPath = exePath
	}

	fmt.Println("\n正在自动安装服务...")

	// 使用NSSM创建服务
	cmd := exec.Command("nssm", "install", serviceName, absPath, "-config", "./config/config.yml")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("执行: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("创建服务失败: %v\n", err)
		os.Exit(1)
	}

	// 启动服务
	cmd = exec.Command("nssm", "start", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("执行: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("启动服务失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n服务安装完成！\n")
	printServiceCommandsWindows(serviceName)
}

// 检查nssm是否可用
func checkNSSMAvailable() bool {
	cmd := exec.Command("nssm", "--version")
	return cmd.Run() == nil
}

// 检查Windows服务是否已存在
func checkServiceExistsWindows(serviceName string) bool {
	cmd := exec.Command("sc", "query", serviceName)
	return cmd.Run() == nil
}

// 打印Windows服务管理命令
func printServiceCommandsWindows(serviceName string) {
	fmt.Println("\n服务管理命令:")
	fmt.Printf("  # 查看状态\n  nssm status %s\n", serviceName)
	fmt.Printf("  # 启动服务\n  nssm start %s\n", serviceName)
	fmt.Printf("  # 停止服务\n  nssm stop %s\n", serviceName)
	fmt.Printf("  # 重启服务\n  nssm restart %s\n", serviceName)
	fmt.Printf("  # 删除服务 (需要先运行 'netZero redo')\n  nssm remove %s confirm\n", serviceName)
}

func startNebula() {
	configPath := "./config/config.yml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("配置文件不存在: %s\n", configPath)
		os.Exit(1)
	}

	var cmd *exec.Cmd

	cmd = exec.Command("./nebula", "-config", configPath)

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
	cmd := exec.Command("sc", "query", "netZero")
	if err := cmd.Run(); err == nil {
		fmt.Println("检测到 netZero 服务正在运行，正在自动停止并删除...")

		// 停止服务
		cmd = exec.Command("nssm", "stop", "netZero")
		if err := cmd.Run(); err != nil {
			fmt.Printf("停止服务失败: %v\n", err)
		} else {
			fmt.Println("服务已停止")
		}

		// 删除服务
		cmd = exec.Command("nssm", "remove", "netZero", "confirm")
		if err := cmd.Run(); err != nil {
			fmt.Printf("删除服务失败: %v\n", err)
		} else {
			fmt.Println("服务已删除")
		}
	}
}
