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
	exePath := "nebula.exe"

	absPath, err := filepath.Abs(exePath)
	if err != nil {
		absPath = exePath
	}

	fmt.Println()
	fmt.Println("=== Windows 服务安装教程 ===")
	fmt.Println()
	fmt.Println("1. 使用 winget 下载 NSSM (Non-Sucking Service Manager):")
	fmt.Println("   winget install NSSM.NSSM")
	fmt.Println()
	fmt.Println("2. 使用 NSSM 创建服务:")
	fmt.Printf("    nssm install netZero \"%s\" \"-config ./config/config.yml\"\n", absPath)
	fmt.Println()
	fmt.Println("3. 启动服务:")
	fmt.Println("   nssm start netZero")
	fmt.Println()
	fmt.Println("4. 其他常用命令:")
	fmt.Println("   - 停止服务: nssm stop netZero")
	fmt.Println("   - 重启服务: nssm restart netZero")
	fmt.Println("   - 删除服务: nssm remove netZero confirm")
	fmt.Println("   - 查看服务: nssm status netZero")
	fmt.Println()
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
