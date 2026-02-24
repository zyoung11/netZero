//go:build windows
// +build windows

package main

import (
	"fmt"
	"path/filepath"
)

func installService() {
	// 直接指定为nebula.exe而不是当前运行程序
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
}
