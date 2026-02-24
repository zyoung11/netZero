//go:build windows
// +build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows/registry"
)

//go:embed favicon.ico
var iconData []byte

const appName = "netZero"

var menuItems struct {
	autoStart *systray.MenuItem
	quit      *systray.MenuItem
}

// go build -ldflags "-s -w -H windowsgui" -buildvcs=false .
func installService() {
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		if err := os.Chdir(exeDir); err != nil {
			log.Printf("警告: 无法切换到工作目录 %s: %v", exeDir, err)
		} else {
			log.Printf("工作目录已更改为: %s", exeDir)
		}
	}
	hideConsole()
	go func() {
		startNebula()
	}()
	systray.Run(onReady, onExit)
}

func startNebula() {
	configPath := "./config/config.yml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("配置文件不存在: %s\n", configPath)
		os.Exit(1)
	}

	var cmd *exec.Cmd

	cmd = exec.Command("./nebula.exe", "-config", configPath)

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

func onReady() {
	systray.SetIcon(iconData)
	systray.SetTitle("AutoStart Shell")
	systray.SetTooltip("系统托盘外壳程序")

	menuItems.autoStart = systray.AddMenuItem("Auto Startup", "切换开机自启")
	go func() {
		for range menuItems.autoStart.ClickedCh {
			toggleAutoStart()
		}
	}()

	systray.AddSeparator()

	menuItems.quit = systray.AddMenuItem("Exit", "退出程序")
	go func() {
		for range menuItems.quit.ClickedCh {
			systray.Quit()
		}
	}()

	refreshMenuState()
	log.Println("托盘外壳程序已启动")
}

func onExit() {
	log.Println("程序退出")
}

func toggleAutoStart() {
	currentState := isAutoStartEnabled()
	newState := !currentState

	if err := setAutoStart(newState); err != nil {
		log.Printf("切换开机自启失败: %v", err)
		return
	}

	refreshMenuState()
}

func refreshMenuState() {
	if isAutoStartEnabled() {
		menuItems.autoStart.SetTitle("✓ Auto Startup")
	} else {
		menuItems.autoStart.SetTitle("Auto Startup")
	}
}

func setAutoStart(enabled bool) error {
	const regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}

	cmd := exePath

	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表失败: %v", err)
	}
	defer key.Close()

	if enabled {
		err = key.SetStringValue(appName, cmd)
		if err != nil {
			return fmt.Errorf("写入注册表失败: %v", err)
		}
		val, _, _ := key.GetStringValue(appName)
		log.Printf("注册表已写入: name=%s, cmd=%s", appName, val)
	} else {
		err = key.DeleteValue(appName)
		if err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("删除注册表项失败: %v", err)
		}
		log.Println("开机自启已禁用")
	}
	return nil
}

func isAutoStartEnabled() bool {
	const regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	_, _, err = key.GetStringValue(appName)
	return err == nil
}

func getConsoleWindow() syscall.Handle {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetConsoleWindow")
	ret, _, _ := proc.Call()
	return syscall.Handle(ret)
}

func hideConsole() {
	hwnd := getConsoleWindow()
	if hwnd == 0 {
		return
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	showWindow := user32.NewProc("ShowWindow")
	showWindow.Call(uintptr(hwnd), uintptr(0))
}
