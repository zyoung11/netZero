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
	"lighthouse/text"
	textarea "lighthouse/textarea"
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

	termimg "github.com/blacktop/go-termimg"
	bbolt "github.com/boltdb/bolt"

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
			runLighthouseDirectly()
		case "list":
			handleList()
		case "service":
			handleService()
		case "redo":
			handleRedo()
		case "phone":
			handlePhone()
		case "help", "-h", "--help":
			printHelp()
		default:
			fmt.Printf("未知命令: %s\n\n", command)
			printHelp()
			os.Exit(1)
		}
	} else {
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
			"phone   - 为手机添加证书",
			"help    - 显示帮助信息",
			"exit    - 退出程序",
		},
	}

	choice := result.RadioList(config)

	switch {
	case strings.Contains(choice, "run"):
		runLighthouseDirectly()
	case strings.Contains(choice, "list"):
		handleList()
	case strings.Contains(choice, "service"):
		handleService()
	case strings.Contains(choice, "redo"):
		handleRedo()
	case strings.Contains(choice, "phone"):
		handlePhone()
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
  phone   为手机添加证书
  help    显示此帮助信息

直接运行程序（不带参数）将显示交互式菜单。
`
	fmt.Print(helpText)
}

func runDBOperation(operation func(db *bbolt.DB) error) error {
	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Printf("关闭数据库时出错: %v\n", err)
		}
	}()
	return operation(db)
}

func runLighthouseDirectly() {
	if _, err := os.Stat("./config"); os.IsNotExist(err) {
		err := os.MkdirAll("./config", 0755)
		if err != nil {
			fmt.Printf("创建config文件夹失败: %v\n", err)
			os.Exit(1)
		}

		err = initLighthouse()
		if err != nil {
			fmt.Printf("初始化失败: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Printf("检查config文件夹失败: %v\n", err)
		os.Exit(1)
	} else {
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
	}

	err := runLighthouse()
	if err != nil {
		fmt.Printf("运行失败: %v\n", err)
		os.Exit(1)
	}
}

func isSudo() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}
	return currentUser.Uid == "0"
}

func initLighthouse() error {
	err := os.MkdirAll("./config", 0755)
	if err != nil {
		return fmt.Errorf("创建config文件夹失败: %w", err)
	}

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

	configContent := generateLighthouseConfig(publicIP)
	err = os.WriteFile("./config.yml", []byte(configContent), 0644)
	if err != nil {
		return fmt.Errorf("写入config.yml失败: %w", err)
	}

	cmd := exec.Command("./nebula-cert", "ca", "-name", "netZero", "-duration", "876000h")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("生成CA证书失败: %w", err)
	}

	cmd = exec.Command("./nebula-cert", "sign", "-name", "lighthouse", "-ip", "192.168.100.1/24", "-groups", "admin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("生成lighthouse证书失败: %w", err)
	}

	files := []string{"ca.crt", "ca.key", "lighthouse.crt", "lighthouse.key", "config.yml"}
	for _, f := range files {
		err = os.Rename(f, filepath.Join("./config", f))
		if err != nil {
			return fmt.Errorf("移动文件 %s 失败: %w", f, err)
		}
	}

	err = runDBOperation(func(db *bbolt.DB) error {
		err := bolt.CreateBucketIfNotExists(db, "users")
		if err != nil {
			return fmt.Errorf("创建users桶失败: %w", err)
		}
		err = bolt.CreateBucketIfNotExists(db, "metaDate")
		if err != nil {
			return fmt.Errorf("创建metaDate桶失败: %w", err)
		}
		err = bolt.PutKV(db, "metaDate", "public_ip", publicIP)
		if err != nil {
			return fmt.Errorf("存储公网IP失败: %w", err)
		}
		err = bolt.PutKV(db, "metaDate", "password", password)
		if err != nil {
			return fmt.Errorf("存储密码失败: %w", err)
		}
		err = bolt.PutKV(db, "users", "lighthouse", "192.168.100.1")
		if err != nil {
			return fmt.Errorf("存储lighthouse信息失败: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
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

relay:
  am_relay: true
  relays: []

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
	app.Get("/cli/list", handleCliList)
	app.Delete("/cli/user/:username", handleCliDeleteUser)

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

	var ip string
	var userCount int
	var publicIP string
	err = runDBOperation(func(db *bbolt.DB) error {
		_, err := bolt.GetKV(db, "users", client.Name)
		if err == nil {
			return fmt.Errorf("Name already exists.")
		}
		userCount, err = bolt.CountBucketKV(db, "users")
		if err != nil {
			return err
		}
		ip = fmt.Sprintf("192.168.100.%d", userCount+1)
		publicIP, err = bolt.GetKV(db, "metaDate", "public_ip")
		if err != nil {
			return err
		}
		err = bolt.PutKV(db, "users", client.Name, ip)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if err.Error() == "Name already exists." {
			return c.Status(409).JSON(fiber.Map{"error": "Name already exists."})
		}
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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
	var ip string
	err := runDBOperation(func(db *bbolt.DB) error {
		var err error
		ip, err = bolt.GetKV(db, "metaDate", "public_ip")
		return err
	})
	if err != nil {
		return "", err
	}
	return ip, nil
}

func getPassword() (string, error) {
	var password string
	err := runDBOperation(func(db *bbolt.DB) error {
		var err error
		password, err = bolt.GetKV(db, "metaDate", "password")
		return err
	})
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
  relays:
    - "192.168.100.1"

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

func handleCliList(c *fiber.Ctx) error {
	var users map[string]string
	err := runDBOperation(func(db *bbolt.DB) error {
		var err error
		users, err = bolt.ScanAll(db, "users")
		return err
	})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "获取用户数据失败"})
	}

	return c.JSON(fiber.Map{"users": users})
}

func handleList() {
	handleListDirect()
}

func handleListDirect() {
	var users map[string]string
	err := runDBOperation(func(db *bbolt.DB) error {
		var err error
		users, err = bolt.ScanAll(db, "users")
		return err
	})
	if err != nil {
		fmt.Printf("获取用户数据失败: %v\n", err)
		os.Exit(1)
	}

	displayAndManageUsers(users)
}

func displayAndManageUsers(users map[string]string) {
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
			deleteUserDirect(username, ip)
		} else {
			fmt.Println("操作已取消")
		}
	} else {
		fmt.Println("操作已取消")
	}
}

func handleCliDeleteUser(c *fiber.Ctx) error {
	username := c.Params("username")

	err := runDBOperation(func(db *bbolt.DB) error {
		_, err := bolt.GetKV(db, "users", username)
		if err != nil {
			return fmt.Errorf("用户不存在")
		}

		err = bolt.DeleteKV(db, "users", username)
		if err != nil {
			return fmt.Errorf("删除用户失败")
		}

		certFile := fmt.Sprintf("./config/%s.crt", username)
		keyFile := fmt.Sprintf("./config/%s.key", username)

		if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("删除证书文件失败: %v\n", err)
		}
		if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("删除密钥文件失败: %v\n", err)
		}

		return nil
	})
	if err != nil {
		if err.Error() == "用户不存在" {
			return c.Status(404).JSON(fiber.Map{"error": "用户不存在"})
		}
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": fmt.Sprintf("用户 '%s' 已删除", username)})
}

func deleteUserDirect(username, ip string) {
	err := runDBOperation(func(db *bbolt.DB) error {
		err := bolt.DeleteKV(db, "users", username)
		if err != nil {
			return err
		}

		certFile := fmt.Sprintf("./config/%s.crt", username)
		keyFile := fmt.Sprintf("./config/%s.key", username)

		if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("删除证书文件失败: %v\n", err)
		}
		if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("删除密钥文件失败: %v\n", err)
		}

		return nil
	})
	if err != nil {
		fmt.Printf("删除用户失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("用户 '%s' 已成功删除\n", username)
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
		checkAndCleanService()

		if err := os.RemoveAll("./config"); err != nil {
			fmt.Printf("删除config文件夹失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("配置已重置，可以重新运行 'lighthouse run'")
	} else {
		fmt.Println("操作已取消")
	}
}

func checkAndCleanService() {
	cmd := exec.Command("systemctl", "status", "lighthouse.service")
	if err := cmd.Run(); err == nil {
		fmt.Println("检测到 lighthouse.service 正在运行，正在自动停止并删除...")

		// 停止并禁用服务
		cmd = exec.Command("systemctl", "disable", "--now", "lighthouse.service")
		if err := cmd.Run(); err != nil {
			fmt.Printf("停止服务失败: %v\n", err)
		} else {
			fmt.Println("服务已停止并禁用")
		}

		// 删除systemd服务文件
		cmd = exec.Command("rm", "-f", "/etc/systemd/system/lighthouse.service")
		if err := cmd.Run(); err != nil {
			fmt.Printf("删除服务文件失败: %v\n", err)
		} else {
			fmt.Println("已删除 /etc/systemd/system/lighthouse.service")
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
	if err := os.Remove("./lighthouse.service"); err == nil {
		fmt.Println("已删除 ./lighthouse.service")
	} else if !os.IsNotExist(err) {
		fmt.Printf("删除 ./lighthouse.service 失败: %v\n", err)
	}
	phoneFiles := []string{"./phone.pub", "./certificate-QR.png", "./ca-QR.png"}
	for _, file := range phoneFiles {
		if err := os.Remove(file); err == nil {
			fmt.Printf("已删除 %s\n", file)
		} else if !os.IsNotExist(err) {
			fmt.Printf("删除 %s 失败: %v\n", file, err)
		}
	}
	certFiles, _ := filepath.Glob("./*.crt")
	keyFiles, _ := filepath.Glob("./*.key")
	for _, file := range append(certFiles, keyFiles...) {
		if err := os.Remove(file); err == nil {
			fmt.Printf("已删除 %s\n", file)
		} else if !os.IsNotExist(err) {
			fmt.Printf("删除 %s 失败: %v\n", file, err)
		}
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

func handlePhone() {
	if _, err := os.Stat("./config"); os.IsNotExist(err) {
		fmt.Println("未初始化，请先运行 'lighthouse run'")
		os.Exit(1)
	}
	requiredFiles := []string{
		"./config/ca.crt",
		"./config/ca.key",
		"./config/data.db",
	}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("缺少必要文件: %s\n", file)
			fmt.Println("请确保已初始化配置")
			os.Exit(1)
		}
	}
	if os.Getenv("TMUX") != "" {
		fmt.Println("错误: 不能在 tmux 会话中运行 phone 命令")
		os.Exit(1)
	}
	if !termimg.KittySupported() && !termimg.SixelSupported() && !termimg.ITerm2Supported() {
		fmt.Println("错误: 终端不支持 Sixel、Kitty 或 iTerm2 图像协议")
		fmt.Println("请确保终端支持其中至少一种协议")
		os.Exit(1)
	}
	fmt.Println("")
	fmt.Println("")
	fmt.Println("请按以下步骤操作：")
	fmt.Println("1. 打开手机端`Nebula`")
	fmt.Println("2. 点击左上方`+`")
	fmt.Println("3. 选择`From scratch`")
	fmt.Println("4. 填写`Name: netZero`")
	fmt.Println("5. 点击`Certificate`复制 Public key")
	fmt.Println()
	name := text.TextInput("请输入名字：")
	if name == "" {
		fmt.Println("名字不能为空")
		os.Exit(1)
	}
	pubKey := textarea.TextAreaInput("请输入公钥：")
	if pubKey == "" {
		fmt.Println("公钥不能为空")
		os.Exit(1)
	}
	err := os.WriteFile("./phone.pub", []byte(pubKey), 0644)
	if err != nil {
		fmt.Printf("保存公钥文件失败: %v\n", err)
		os.Exit(1)
	}
	var userCount int
	var publicIP string
	err = runDBOperation(func(db *bbolt.DB) error {
		_, err := bolt.GetKV(db, "users", name)
		if err == nil {
			return fmt.Errorf("名字已存在")
		}
		count, err := bolt.CountBucketKV(db, "users")
		if err != nil {
			return err
		}
		userCount = count
		ip, err := bolt.GetKV(db, "metaDate", "public_ip")
		if err != nil {
			return err
		}
		publicIP = ip
		return nil
	})
	if err != nil {
		fmt.Printf("数据库操作失败: %v\n", err)
		os.Exit(1)
	}
	ip := fmt.Sprintf("192.168.100.%d", userCount+1)
	cmd := exec.Command("./nebula-cert", "sign", "-in-pub", "phone.pub", "-ca-crt", "./config/ca.crt", "-ca-key", "./config/ca.key", "-name", name, "-ip", ip+"/24", "--groups", "admin", "-out-qr", "certificate-QR.png")
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("生成证书二维码失败: %v\n", err)
		os.Exit(1)
	}
	cmd = exec.Command("./nebula-cert", "print", "-path", "./config/ca.crt", "-out-qr", "ca-QR.png")
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("生成CA二维码失败: %v\n", err)
		os.Exit(1)
	}
	err = runDBOperation(func(db *bbolt.DB) error {
		return bolt.PutKV(db, "users", name, ip)
	})
	if err != nil {
		fmt.Printf("保存用户到数据库失败: %v\n", err)
	}
	fmt.Println("")
	fmt.Println("Certificate QR Code")
	termimg.PrintFile("certificate-QR.png")
	fmt.Println("")
	fmt.Println("")
	fmt.Println("CA QR Code")
	termimg.PrintFile("ca-QR.png")
	fmt.Println("")
	fmt.Println("")
	fmt.Println("请点击 Hosts -> Add a new entry 输入：")
	fmt.Printf("Nebula IP: 192.168.100.1\n")
	fmt.Printf("Lighthouse: ✓\n")
	fmt.Printf("public ip: %s\n", publicIP)
	fmt.Printf("port: 4242\n")
	os.Remove("./phone.pub")
	os.Remove("./certificate-QR.png")
	os.Remove("./ca-QR.png")
	os.Remove(fmt.Sprintf("./%s.crt", name))
	os.Remove(fmt.Sprintf("./%s.key", name))
}
