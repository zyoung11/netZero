//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func init() {
	installServiceFunc = installWindowsService
}

func installWindowsService() {
	// 检查nssm.exe是否存在
	nssmPath := "./nssm/nssm.exe"
	if _, err := os.Stat(nssmPath); os.IsNotExist(err) {
		fmt.Printf("nssm.exe未找到: %s\n", nssmPath)
		fmt.Println("请确保nssm目录存在且包含nssm.exe")
		os.Exit(1)
	}

	// 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		os.Exit(1)
	}

	exePath, err = filepath.Abs(exePath)
	if err != nil {
		fmt.Printf("获取绝对路径失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("正在安装Windows服务...")
	fmt.Printf("程序路径: %s\n", exePath)

	// 执行nssm安装命令
	cmd := exec.Command(nssmPath, "install", "netzero", exePath, "run")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("执行命令: %s\n", cmd.String())

	if err := cmd.Run(); err != nil {
		fmt.Printf("安装服务失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n服务安装完成！")
	fmt.Println("请执行以下命令启动服务:")
	fmt.Println("  .\\nssm\\nssm.exe start netzero")
	fmt.Println("\n其他有用命令:")
	fmt.Println("  .\\nssm\\nssm.exe status netzero    # 查看状态")
	fmt.Println("  .\\nssm\\nssm.exe stop netzero     # 停止服务")
	fmt.Println("  .\\nssm\\nssm.exe restart netzero  # 重启服务")
	fmt.Println("  .\\nssm\\nssm.exe remove netzero   # 删除服务")
}
