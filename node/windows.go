//go:build windows
// +build windows

package main

import "fmt"

func installService() {
	fmt.Println("=== Windows 服务安装教程 ===")
	fmt.Println()
	fmt.Println("1. 使用 winget 下载 NSSM (Non-Sucking Service Manager):")
	fmt.Println("   winget install nssm")
	fmt.Println()
	fmt.Println("2. 使用 NSSM 创建服务:")
	fmt.Println("   nssm install netZero \"%CD%\\netZero.exe\"")
	fmt.Println()
	fmt.Println("3. 设置服务参数:")
	fmt.Println("   在 NSSM 界面中，设置参数为: -config ./config/config.yml")
	fmt.Println()
	fmt.Println("4. 启动服务:")
	fmt.Println("   nssm start netZero")
	fmt.Println()
	fmt.Println("5. 其他常用命令:")
	fmt.Println("   - 停止服务: nssm stop netZero")
	fmt.Println("   - 重启服务: nssm restart netZero")
	fmt.Println("   - 删除服务: nssm remove netZero confirm")
	fmt.Println()
	fmt.Println("注意: 请确保在 netZero.exe 所在目录运行上述命令。")
	fmt.Println("如果遇到权限问题，请以管理员身份运行命令提示符。")
}

func startNebula() {
}
