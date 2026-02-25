package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"lighthouse/bolt"
	"lighthouse/result"
	"lighthouse/table"
	"lighthouse/texts"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"charm.land/bubbles/v2/textinput"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/term"
)

func main() {
	// 检查sudo权限
	if !isSudo() {
		fmt.Println("需要sudo权限运行此程序")
		os.Exit(1)
	}

	// 处理命令行参数
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "run":
			// 直接运行程序
			runLighthouseDirectly()
		case "list":
			// 显示用户列表
			handleList()
		case "service":
			// 安装系统服务
			handleService()
		case "redo":
			// 重置所有配置
			handleRedo()
		case "help", "-h", "--help":
			// 显示帮助信息
			printHelp()
		default:
			fmt.Printf("未知命令: %s\n\n", command)
			printHelp()
			os.Exit(1)
		}
	} else {
		// 如果没有参数，显示交互式菜单
		showInteractiveMenu()
	}
}

func showInteractiveMenu() {
	config := result.RadioConfig{
		Question: "请选择要执行的操作:",
		Options: []string{
			"run     - 启动lighthouse服务",
			"list    - 显示用户列表",
			"service - 安装系统服务",
			"redo    - 重置所有配置",
			"help    - 显示帮助信息",
			"exit    - 退出程序",
		},
	}

	choice := result.RadioList(config)

	// 解析选择
	switch {
	case strings.Contains(choice, "run"):
		runLighthouseDirectly()
	case strings.Contains(choice, "list"):
		handleList()
	case strings.Contains(choice, "service"):
		handleService()
	case strings.Contains(choice, "redo"):
		handleRedo()
	case strings.Contains(choice, "help"):
		printHelp()
	case strings.Contains(choice, "exit"):
		fmt.Println("程序退出")
		os.Exit(0)
	default:
		fmt.Println("无效选择")
		os.Exit(1)
	}
}

func printHelp() {
	helpText := `
lighthouse - netZero服务器端

用法: lighthouse [命令]

命令:
  run     启动lighthouse服务
  list    显示用户列表
  service 安装系统服务（开机自启）
  redo    重置所有配置
  help    显示此帮助信息

直接运行程序（不带参数）将显示交互式菜单。
`
	fmt.Print(helpText)
}

func runLighthouseDirectly() {
	// 检查config文件夹是否存在
	if _, err := os.Stat("./config"); os.IsNotExist(err) {
		// 先创建config文件夹
		err := os.MkdirAll("./config", 0755)
		if err != nil {
			fmt.Printf("创建config文件夹失败: %v\n", err)
			os.Exit(1)
		}

		// 打开数据库连接（会创建data.db文件）
		bolt.DB, err = bolt.OpenDB("./config/data.db")
		if err != nil {
			fmt.Printf("打开数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer bolt.DB.Close()

		// 初始化流程
		err = initLighthouse()
		if err != nil {
			fmt.Printf("初始化失败: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Printf("检查config文件夹失败: %v\n", err)
		os.Exit(1)
	} else {
		// config文件夹已存在，检查所有必需文件
		requiredFiles := []string{
			"./config/ca.crt",
			"./config/lighthouse.crt",
			"./config/lighthouse.key",
			"./config/data.db",
			"./config/ca.key",
			"./config/config.yml",
		}

		missingFiles := []string{}
		for _, file := range requiredFiles {
			if _, err := os.Stat(file); os.IsNotExist(err) {
				missingFiles = append(missingFiles, file)
			}
		}

		if len(missingFiles) > 0 {
			fmt.Println("配置不完整，缺少以下文件:")
			for _, file := range missingFiles {
				fmt.Printf("  - %s\n", file)
			}
			fmt.Println("\n建议删除 ./config/ 目录并重新初始化程序")
			os.Exit(1)
		}

		// 所有文件都存在，打开数据库连接
		var err error
		bolt.DB, err = bolt.OpenDB("./config/data.db")
		if err != nil {
			fmt.Printf("打开数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer bolt.DB.Close()
	}

	// 运行流程
	err := runLighthouse()
	if err != nil {
		fmt.Printf("运行失败: %v\n", err)
		os.Exit(1)
	}
}

func isSudo() bool {
	// 检查是否为root用户
	currentUser, err := user.Current()
	if err != nil {
		return false
	}
	return currentUser.Uid == "0"
}

func initLighthouse() error {
	// 1. 创建config文件夹
	err := os.MkdirAll("./config", 0755)
	if err != nil {
		return fmt.Errorf("创建config文件夹失败: %w", err)
	}

	// 2. 创建users和metaDate桶
	err = bolt.CreateBucketIfNotExists(bolt.DB, "users")
	if err != nil {
		return fmt.Errorf("创建users桶失败: %w", err)
	}
	err = bolt.CreateBucketIfNotExists(bolt.DB, "metaDate")
	if err != nil {
		return fmt.Errorf("创建metaDate桶失败: %w", err)
	}

	// 3. 使用texts库获取用户输入的公网IP和密码
	config := texts.TextInputsConfig{
		Inputs: []texts.InputConfig{
			{Placeholder: "请输入公网IP"},
			{Placeholder: "请输入密码", EchoMode: textinput.EchoPassword},
		},
	}

	results := texts.TextInputs(config)
	if results == nil {
		return fmt.Errorf("操作已取消")
	}

	if len(results) != 2 {
		return fmt.Errorf("输入数据不完整")
	}

	publicIP := strings.TrimSpace(results[0])
	password := strings.TrimSpace(results[1])

	if net.ParseIP(publicIP) == nil {
		return fmt.Errorf("无效的IP地址")
	}

	if password == "" {
		return fmt.Errorf("密码不能为空")
	}

	// 4. 将公网IP和密码存储到metaDate桶
	err = bolt.PutKV(bolt.DB, "metaDate", "public_ip", publicIP)
	if err != nil {
		return fmt.Errorf("存储公网IP失败: %w", err)
	}
	err = bolt.PutKV(bolt.DB, "metaDate", "password", password)
	if err != nil {
		return fmt.Errorf("存储密码失败: %w", err)
	}

	// 5. 合成config.yml
	configContent := generateLighthouseConfig(publicIP)
	err = os.WriteFile("./config.yml", []byte(configContent), 0644)
	if err != nil {
		return fmt.Errorf("写入config.yml失败: %w", err)
	}

	// 6. 生成CA证书
	cmd := exec.Command("./nebula-cert", "ca", "-name", "netZero", "-duration", "876000h")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("生成CA证书失败: %w", err)
	}

	// 7. 生成lighthouse证书
	cmd = exec.Command("./nebula-cert", "sign", "-name", "lighthouse", "-ip", "192.168.100.1/24", "-groups", "admin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("生成lighthouse证书失败: %w", err)
	}

	// 8. 移动文件到config目录
	files := []string{"ca.crt", "ca.key", "lighthouse.crt", "lighthouse.key", "config.yml"}
	for _, f := range files {
		err = os.Rename(f, filepath.Join("./config", f))
		if err != nil {
			return fmt.Errorf("移动文件 %s 失败: %w", f, err)
		}
	}

	// 9. 存储lighthouse信息到users桶
	err = bolt.PutKV(bolt.DB, "users", "lighthouse", "192.168.100.1")
	if err != nil {
		return fmt.Errorf("存储lighthouse信息失败: %w", err)
	}

	return nil
}

func generateLighthouseConfig(publicIP string) string {
	return fmt.Sprintf(`
pki:
  ca: ./config/ca.crt
  cert: ./config/lighthouse.crt
  key: ./config/lighthouse.key

static_host_map:
  "192.168.100.1": ["%s:4242"]

lighthouse:
  am_lighthouse: true
  serve_dns: false

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

cipher: aes

tun:
  disabled: false
  dev: netzero
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: 4242
      proto: any
      host: any

    - port: 9090
      proto: any
      group: admin

    - port: 9090
      proto: any
      group: guest

    - port: 9090
      proto: any
      group: untrusted

    - port: 80
      proto: any
      group: admin

    - port: 80
      proto: any
      group: guest

    - port: 443
      proto: any
      group: admin

    - port: 443
      proto: any
      group: guest

    - port: any
      proto: any
      group: admin

    - port: any
      proto: icmp
      group: any
`, publicIP)
}

func runLighthouse() error {
	// 创建context用于取消操作
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 启动web服务
	go startWebService()

	// 启动nebula
	cmd := exec.Command("./nebula", "-config", "./config/config.yml")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 设置进程组，确保子进程能一起被终止
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("启动nebula失败: %w", err)
	}

	// 创建goroutine等待进程退出
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// 等待信号或进程退出
	select {
	case sig := <-sigChan:
		fmt.Printf("收到信号: %v，正在终止进程...\n", sig)

		// 发送SIGTERM给进程组
		if cmd.Process != nil {
			// 发送SIGTERM给整个进程组
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)

			// 等待进程退出
			select {
			case <-time.After(5 * time.Second):
				// 如果5秒后还没退出，发送SIGKILL
				fmt.Println("进程未在5秒内退出，强制终止...")
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			case err := <-done:
				if err != nil {
					fmt.Printf("进程已退出，错误: %v\n", err)
				} else {
					fmt.Println("进程已正常退出")
				}
				return nil
			}
		}

		// 等待最终退出
		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("进程最终退出，错误: %v\n", err)
			}
		case <-time.After(2 * time.Second):
			fmt.Println("进程强制终止完成")
		}

		return fmt.Errorf("程序被信号终止: %v", sig)

	case err := <-done:
		if err != nil {
			return fmt.Errorf("nebula进程异常退出: %w", err)
		}
		return nil
	}
}

func startWebService() {
	app := fiber.New()

	app.Post("/init", handleInit)

	err := app.Listen("0.0.0.0:9090")
	if err != nil {
		fmt.Printf("启动web服务失败: %v\n", err)
	}
}

func handleInit(c *fiber.Ctx) error {
	type Request struct {
		Info string `json:"info"`
	}
	type ClientInfo struct {
		Name        string `json:"name"`
		Permissions string `json:"permissions"`
		Duration    string `json:"duration"`
	}
	type Response struct {
		Info string `json:"info"`
	}
	type CertData struct {
		CA     string `json:"ca"`
		CRT    string `json:"crt"`
		KEY    string `json:"key"`
		Config string `json:"config"`
		IP     string `json:"ip"`
		Name   string `json:"name"`
	}

	var req Request
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	password, err := getPassword()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to get password"})
	}

	decrypted, err := decrypt(password, req.Info)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "decryption failed"})
	}

	var client ClientInfo
	if err := json.Unmarshal([]byte(decrypted), &client); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid client info"})
	}

	if client.Permissions != "admin" && client.Permissions != "guest" && client.Permissions != "untrusted" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid permissions"})
	}

	// 检查机器名是否已存在
	_, err = bolt.GetKV(bolt.DB, "users", client.Name)
	if err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Name already exists."})
	}

	userCount, err := bolt.CountBucketKV(bolt.DB, "users")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to count users"})
	}
	ip := fmt.Sprintf("192.168.100.%d", userCount+1)

	publicIP, err := getPublicIP()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to get public IP"})
	}

	args := []string{
		"sign",
		"-name", client.Name,
		"-ip", ip + "/24",
		"-groups", client.Permissions,
	}
	if client.Permissions != "admin" && strings.TrimSpace(client.Duration) != "" {
		args = append(args, "-duration", strings.TrimSpace(client.Duration))
	}
	args = append(args, "-ca-crt", "./config/ca.crt", "-ca-key", "./config/ca.key")
	cmd := exec.Command("./nebula-cert", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "certificate generation failed"})
	}

	caContent, err := os.ReadFile("./config/ca.crt")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to read ca.crt"})
	}
	crtContent, err := os.ReadFile(fmt.Sprintf("./%s.crt", client.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to read client cert"})
	}
	keyContent, err := os.ReadFile(fmt.Sprintf("./%s.key", client.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to read client key"})
	}

	// 存储用户信息到users桶
	err = bolt.PutKV(bolt.DB, "users", client.Name, ip)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to store user info"})
	}

	os.Remove(fmt.Sprintf("./%s.crt", client.Name))
	os.Remove(fmt.Sprintf("./%s.key", client.Name))

	configContent := generateClientConfig(publicIP, client.Name, client.Permissions)
	certData := CertData{
		CA:     string(caContent),
		CRT:    string(crtContent),
		KEY:    string(keyContent),
		Config: configContent,
		IP:     ip,
		Name:   client.Name,
	}
	certJSON, err := json.Marshal(certData)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to marshal cert data"})
	}

	encryptedResponse, err := encrypt(password, string(certJSON))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "encryption failed"})
	}

	return c.JSON(Response{Info: encryptedResponse})
}

func getPublicIP() (string, error) {
	ip, err := bolt.GetKV(bolt.DB, "metaDate", "public_ip")
	if err != nil {
		return "", err
	}
	return ip, nil
}

func getPassword() (string, error) {
	password, err := bolt.GetKV(bolt.DB, "metaDate", "password")
	if err != nil {
		return "", err
	}
	return password, nil
}

func generateFirewallRules(permissions string) string {
	switch permissions {
	case "admin":
		return `
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: admin

    - port: any
      proto: any
      group: guest`
	case "guest":
		return `
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: admin

    - port: any
      proto: any
      group: guest`
	case "untrusted":
		return `
firewall:
  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      group: any`
	default:
		return ""
	}
}

func generateClientConfig(publicIP, clientName, permissions string) string {
	firewallRules := generateFirewallRules(permissions)
	return fmt.Sprintf(`
pki:
  ca: ./config/ca.crt
  cert: ./config/%s.crt
  key: ./config/%s.key

static_host_map:
  "192.168.100.1": ["%s:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"

listen:
  host: 0.0.0.0
  port: 0

punchy:
  punch: true
  respond: true

relay:
  am_relay: false
  use_relays: true

cipher: aes

tun:
  dev: netZero
  mtu: 1300

logging:
  level: info

%s`, clientName, clientName, publicIP, firewallRules)
}

// 派生AES密钥
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// 加密解密函数
func encrypt(key, plaintext string) (string, error) {
	derivedKey := deriveKey(key)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key, ciphertext string) (string, error) {
	derivedKey := deriveKey(key)
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return string(data), nil
}

func readPassword() (string, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var password []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		ch := buf[0]
		if ch == '\r' || ch == '\n' {
			break
		} else if ch == 127 || ch == 8 {
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
		} else {
			password = append(password, ch)
			fmt.Print("*")
		}
	}
	fmt.Println()
	return string(password), nil
}

func handleList() {
	// 打开数据库连接
	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		fmt.Printf("打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// 获取所有用户数据
	users, err := bolt.ScanAll(db, "users")
	if err != nil {
		fmt.Printf("获取用户数据失败: %v\n", err)
		os.Exit(1)
	}

	if len(users) == 0 {
		fmt.Println("没有用户数据")
		return
	}

	// 准备表格数据
	headers := []string{"用户名", "IP地址"}
	rows := [][]string{}

	for username, ip := range users {
		rows = append(rows, []string{username, ip})
	}

	// 显示表格
	config := table.TableConfig{
		Headers: headers,
		Rows:    rows,
	}

	selectedRow := table.ShowTable(config)
	if selectedRow != nil && len(selectedRow) >= 2 {
		username := selectedRow[0]
		ip := selectedRow[1]

		// 询问是否删除
		deleteConfig := result.RadioConfig{
			Question: fmt.Sprintf("是否要删除用户 '%s' (IP: %s)?", username, ip),
			Options:  []string{"是", "否"},
		}

		choice := result.RadioList(deleteConfig)
		if choice == "是" {
			// 删除用户
			err := bolt.DeleteKV(db, "users", username)
			if err != nil {
				fmt.Printf("删除用户失败: %v\n", err)
				os.Exit(1)
			}

			// 删除证书文件
			certFile := fmt.Sprintf("./config/%s.crt", username)
			keyFile := fmt.Sprintf("./config/%s.key", username)

			if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
				fmt.Printf("删除证书文件失败: %v\n", err)
			}
			if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
				fmt.Printf("删除密钥文件失败: %v\n", err)
			}

			fmt.Printf("用户 '%s' 已成功删除\n", username)
		} else {
			fmt.Println("操作已取消")
		}
	} else {
		fmt.Println("操作已取消")
	}
}

func handleService() {
	// 检查是否已初始化（config文件夹是否存在）
	if _, err := os.Stat("./config"); os.IsNotExist(err) {
		fmt.Println("未初始化，请先运行 'lighthouse run'")
		os.Exit(1)
	}

	installService()
}

func handleRedo() {
	config := result.RadioConfig{
		Question: "警告: 此操作将删除所有配置文件和证书！确认要重置所有配置吗？",
		Options:  []string{"是", "否"},
	}

	choice := result.RadioList(config)

	if choice == "是" {
		// 删除config文件夹
		if err := os.RemoveAll("./config"); err != nil {
			fmt.Printf("删除config文件夹失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("配置已重置，可以重新运行 'lighthouse run'")
	} else {
		fmt.Println("操作已取消")
	}
}

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		os.Exit(1)
	}

	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=lighthouse netZero Service
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
