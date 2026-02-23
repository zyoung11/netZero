package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"lighthouse/bolt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/term"
)

func main() {
	// 检查sudo权限
	if !isSudo() {
		fmt.Println("需要sudo权限运行此程序")
		os.Exit(1)
	}

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
		// config文件夹已存在，打开数据库连接
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

	// 3. 获取用户输入的公网IP和密码
	fmt.Print("请输入公网IP: ")
	var publicIP string
	fmt.Scanln(&publicIP)
	publicIP = strings.TrimSpace(publicIP)
	if net.ParseIP(publicIP) == nil {
		return fmt.Errorf("无效的IP地址")
	}

	fmt.Print("请输入密码: ")
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("读取密码失败: %w", err)
	}
	password = strings.TrimSpace(password)
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
	return fmt.Sprintf(`pki:
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
      action: accept

  inbound:
    - port: 4242
      proto: any
      host: any
      action: accept

    - port: any
      proto: any
      host:
        - group: "admin"
      action: accept

    - port: any
      proto: any
      host: any
      action: drop`, publicIP)
}

func runLighthouse() error {
	// 启动web服务
	go startWebService()

	// 启动nebula
	cmd := exec.Command("./nebula", "-config", "./config/config.yml")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("启动nebula失败: %w", err)
	}

	// 等待进程退出
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("nebula进程异常退出: %w", err)
	}
	return nil
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
	if client.Permissions != "admin" {
		args = append(args, "-duration", client.Duration)
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
		return `firewall:
  outbound:
    - port: any
      proto: any
      host: any
      action: accept

  inbound:
    - port: any
      proto: any
      host: any
      action: accept`
	case "guest":
		return `firewall:
  outbound:
    - port: any
      proto: any
      host: any
      action: accept

  inbound:
    - port: any
      proto: any
      host:
        - group: "admin"
        - group: "untrusted"
      action: accept

    - port: any
      proto: any
      host: any
      action: drop`
	case "untrusted":
		return `firewall:
  outbound:
    - port: any
      proto: any
      host: any
      action: accept

  inbound:
    - port: any
      proto: any
      host:
        - group: "admin"
        - group: "guest"
      action: accept

    - port: any
      proto: any
      host: any
      action: drop`
	default:
		return ""
	}
}

func generateClientConfig(publicIP, clientName, permissions string) string {
	firewallRules := generateFirewallRules(permissions)
	return fmt.Sprintf(`pki:
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
