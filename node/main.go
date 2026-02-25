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
	"net"
	"net/http"
	"netZero/bolt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) == 1 ||
		os.Args[1] == "help" ||
		os.Args[1] == "-help" ||
		os.Args[1] == "--help" ||
		os.Args[1] == "-h" {
		printHelp()
		return
	}

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "run":
		handleRun()
	case "join":
		handleJoin()
	case "service":
		handleService()
	case "invite":
		handleInvite()
	case "redo":
		handleRedo()
	case "ip":
		handleIP()
	default:
		fmt.Printf("未知命令: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	helpText := `netZero - 分布式VPN客户端

用法: netZero [命令]

命令:
  run     启动或初始化netZero连接
  join    通过邀请码加入网络
  service 安装系统服务（开机自启）
  invite  生成邀请码（仅管理员）
  redo    重置所有配置
  ip      显示分配的IP地址
  help    显示此帮助信息

示例:
  netZero run      # 初始化并启动连接
  netZero join     # 通过邀请码加入
  netZero service  # 安装为系统服务
  netZero invite   # 生成邀请码给其他用户

`
	fmt.Print(helpText)
}

// 状态检查函数
func checkConnectionState() string {
	// 检查是否能连接到192.168.100.1
	if !canConnectToGateway() {
		return "disconnected"
	}

	// 检查证书文件是否存在
	hasCertFiles := false
	if entries, err := os.ReadDir("./config"); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key") {
				hasCertFiles = true
				break
			}
		}
	}

	if !hasCertFiles {
		return "disconnected"
	}

	// 检查证书中的groups是否包含admin
	if isAdminFromCert() {
		return "connected_admin"
	}

	return "connected_user"
}

// 检查是否能连接到网关
func canConnectToGateway() bool {
	conn, err := net.DialTimeout("tcp", "192.168.100.1:9090", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 从证书中检查是否为管理员
func isAdminFromCert() bool {
	return checkCertIsAdmin()
}

// 检查证书是否为管理员
func checkCertIsAdmin() bool {
	// 查找证书文件
	certFiles, err := filepath.Glob("./config/*.crt")
	if err != nil || len(certFiles) == 0 {
		return false
	}

	// 遍历所有证书文件，跳过CA证书
	for _, certFile := range certFiles {
		if strings.Contains(certFile, "ca.crt") {
			continue // 跳过CA证书
		}

		// 使用nebula-cert工具解析证书
		cmd := exec.Command("./nebula-cert", "print", "-path", certFile)
		output, err := cmd.Output()
		if err != nil {
			continue // 跳过解析失败的证书
		}

		// 解析JSON输出
		var certInfo map[string]interface{}
		if err := json.Unmarshal(output, &certInfo); err != nil {
			continue // 跳过JSON解析失败的证书
		}

		// 检查details.groups是否包含admin
		if details, ok := certInfo["details"].(map[string]interface{}); ok {
			if groups, ok := details["groups"].([]interface{}); ok {
				for _, group := range groups {
					if groupStr, ok := group.(string); ok && groupStr == "admin" {
						return true
					}
				}
			}
		}
	}

	return false
}

func isAdmin() bool {
	return checkConnectionState() == "connected_admin"
}

func isConnected() bool {
	state := checkConnectionState()
	return state == "connected_admin" || state == "connected_user"
}

// 从lighthouse复制的加密解密函数
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

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

func handleRun() {
	state := checkConnectionState()

	switch state {
	case "disconnected":
		err := adminInit()
		if err != nil {
			fmt.Printf("初始化失败: %v\n", err)
			os.Exit(1)
		}
		startNebula()
	case "connected_admin", "connected_user":
		startNebula()
	default:
		os.Exit(1)
	}
}

func handleJoin() {
	state := checkConnectionState()

	if state != "disconnected" {
		fmt.Println("当前已连接，如需重新加入请使用: netZero redo")
		os.Exit(1)
	}

	// 1. 创建config文件夹
	if err := os.MkdirAll("./config", 0755); err != nil {
		fmt.Printf("创建config文件夹失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 获取邀请码
	var invitationCode string
	fmt.Print("请输入邀请码: ")
	fmt.Scanln(&invitationCode)
	invitationCode = strings.TrimSpace(invitationCode)
	if invitationCode == "" {
		fmt.Println("邀请码不能为空")
		os.Exit(1)
	}

	// 3. 解析邀请码
	certData, err := parseInvitationCode(invitationCode)
	if err != nil {
		fmt.Printf("解析邀请码失败: %v\n", err)
		os.Exit(1)
	}

	// 4. 使用API返回的名字
	if certData.Name == "" {
		fmt.Println("错误：API返回的名字为空")
		os.Exit(1)
	}

	// 5. 保存证书和配置文件
	if err := saveCertFiles(certData); err != nil {
		fmt.Printf("保存证书文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("加入网络成功！")
	fmt.Println("请使用 'netZero run' 启动连接")
}

// 解析邀请码
func parseInvitationCode(code string) (*CertResponse, error) {
	// Base64解码
	decoded, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %w", err)
	}

	// 解析JSON
	var certData CertResponse
	if err := json.Unmarshal(decoded, &certData); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}

	// 验证必要字段
	if certData.CA == "" || certData.CRT == "" || certData.KEY == "" || certData.Config == "" || certData.IP == "" {
		return nil, fmt.Errorf("邀请码缺少必要字段")
	}

	return &certData, nil
}

func handleService() {
	if !isConnected() {
		fmt.Println("未连接，请先运行 'netZero run' 或 'netZero join'")
		os.Exit(1)
	}

	installService()
}

func handleInvite() {
	if !isAdmin() {
		fmt.Println("仅管理员可以生成邀请码")
		os.Exit(1)
	}

	// 获取用户输入
	name, permissions, duration, err := getInviteInput()
	if err != nil {
		fmt.Printf("输入错误: %v\n", err)
		os.Exit(1)
	}

	// 从数据库获取公网IP和密码
	publicIP, password, err := getConfigFromDB()
	if err != nil {
		fmt.Printf("获取配置失败: %v\n", err)
		os.Exit(1)
	}

	// 发送请求获取证书数据
	certData, err := sendInitRequest(publicIP, password, name, permissions, duration)
	if err != nil {
		fmt.Printf("生成邀请码失败: %v\n", err)
		os.Exit(1)
	}

	// 将证书数据转换为JSON并Base64编码
	invitationCode, err := generateInvitationCode(certData)
	if err != nil {
		fmt.Printf("生成邀请码失败: %v\n", err)
		os.Exit(1)
	}

	// 保存到文件
	if err := os.WriteFile("./Invitation.txt", []byte(invitationCode), 0644); err != nil {
		fmt.Printf("保存邀请码文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("邀请码已生成并保存到 ./Invitation.txt")
	fmt.Println("请将此文件发送给需要加入的用户")
}

// 获取邀请输入
func getInviteInput() (string, string, string, error) {
	var name, permissions, duration string

	fmt.Print("请输入用户名: ")
	fmt.Scanln(&name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", "", fmt.Errorf("用户名不能为空")
	}

	for {
		fmt.Print("请选择权限 (guest/untrusted): ")
		fmt.Scanln(&permissions)
		permissions = strings.TrimSpace(strings.ToLower(permissions))
		if permissions == "guest" || permissions == "untrusted" {
			break
		}
		fmt.Println("权限必须是 'guest' 或 'untrusted'")
	}

	fmt.Print("请输入授权时长 (例如: 8760h，直接回车表示无期限): ")
	fmt.Scanln(&duration)
	duration = strings.TrimSpace(duration)
	// 允许为空，表示无期限

	return name, permissions, duration, nil
}

// 从数据库获取配置（仅管理员）
func getConfigFromDB() (string, string, error) {
	// 检查是否为管理员
	if !isAdmin() {
		return "", "", fmt.Errorf("仅管理员可以获取配置")
	}

	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		return "", "", fmt.Errorf("打开数据库失败: %w", err)
	}
	defer db.Close()

	publicIP, err := bolt.GetKV(db, "metaDate", "public_ip")
	if err != nil {
		return "", "", fmt.Errorf("获取公网IP失败: %w", err)
	}

	password, err := bolt.GetKV(db, "metaDate", "password")
	if err != nil {
		return "", "", fmt.Errorf("获取密码失败: %w", err)
	}

	return publicIP, password, nil
}

// 生成邀请码
func generateInvitationCode(certData *CertResponse) (string, error) {
	// 转换为JSON
	jsonData, err := json.Marshal(certData)
	if err != nil {
		return "", fmt.Errorf("JSON编码失败: %w", err)
	}

	// Base64编码
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return encoded, nil
}

func handleRedo() {
	fmt.Println("警告: 此操作将删除所有配置文件和证书！")
	fmt.Print("确认要重置所有配置吗？(输入 'yes' 确认): ")

	var confirmation string
	fmt.Scanln(&confirmation)
	confirmation = strings.TrimSpace(strings.ToLower(confirmation))

	if confirmation != "yes" {
		fmt.Println("操作已取消")
		return
	}

	// 删除config文件夹
	if err := os.RemoveAll("./config"); err != nil {
		fmt.Printf("删除config文件夹失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("配置已重置，可以重新运行 'netZero run' 或 'netZero join'")
}

func handleIP() {
	if !isConnected() {
		fmt.Println("未连接，请先运行 'netZero run' 或 'netZero join'")
		os.Exit(1)
	}

	ip, err := getIP()
	if err != nil {
		fmt.Printf("获取IP失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("您的IP地址: %s\n", ip)
}

// 获取IP地址（统一从数据库获取）
func getIP() (string, error) {
	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		return "", fmt.Errorf("打开数据库失败: %w", err)
	}
	defer db.Close()

	ip, err := bolt.GetKV(db, "metaDate", "ip")
	if err != nil {
		return "", fmt.Errorf("从数据库读取IP失败: %w", err)
	}

	return ip, nil
}

// 管理员初始化流程
func adminInit() error {
	// 1. 创建config文件夹
	if err := os.MkdirAll("./config", 0755); err != nil {
		return fmt.Errorf("创建config文件夹失败: %w", err)
	}

	// 2. 获取用户输入
	publicIP, password, name, err := getUserInput()
	if err != nil {
		return err
	}

	// 3. 加密并发送请求
	responseData, err := sendInitRequest(publicIP, password, name, "admin", "8760h")
	if err != nil {
		return fmt.Errorf("初始化请求失败: %w", err)
	}

	// 4. 保存证书和配置文件
	if err := saveCertFiles(responseData); err != nil {
		return fmt.Errorf("保存证书文件失败: %w", err)
	}

	// 5. 创建管理员数据库（管理员需要存储publicIP和password）
	// 注意：saveCertFiles已经创建了数据库，但我们需要更新它来包含publicIP和password
	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}
	defer db.Close()

	// 存储公网IP和密码
	if err := bolt.PutKV(db, "metaDate", "public_ip", publicIP); err != nil {
		return fmt.Errorf("存储公网IP失败: %w", err)
	}
	if err := bolt.PutKV(db, "metaDate", "password", password); err != nil {
		return fmt.Errorf("存储密码失败: %w", err)
	}

	fmt.Println("管理员初始化完成")
	return nil
}

// 获取用户输入
func getUserInput() (string, string, string, error) {
	var publicIP, password, name string

	fmt.Print("请输入公网IP: ")
	fmt.Scanln(&publicIP)
	publicIP = strings.TrimSpace(publicIP)
	if net.ParseIP(publicIP) == nil {
		return "", "", "", fmt.Errorf("无效的IP地址")
	}

	fmt.Print("请输入密码: ")
	password, err := readPassword()
	if err != nil {
		return "", "", "", fmt.Errorf("读取密码失败: %w", err)
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return "", "", "", fmt.Errorf("密码不能为空")
	}

	fmt.Print("请输入名字: ")
	fmt.Scanln(&name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", "", fmt.Errorf("名字不能为空")
	}

	return publicIP, password, name, nil
}

// 发送初始化请求
func sendInitRequest(publicIP, password, name, permissions, duration string) (*CertResponse, error) {
	// 构造请求JSON
	requestData := map[string]string{
		"name":        name,
		"permissions": permissions,
		"duration":    duration,
	}

	requestJSON, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("JSON编码失败: %w", err)
	}

	// 加密
	encryptedInfo, err := encrypt(password, string(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}

	// 构造HTTP请求
	reqBody := map[string]string{
		"info": encryptedInfo,
	}
	reqJSON, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("http://%s:9090/init", publicIP)

	// 创建HTTP客户端，设置30秒超时
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(url, "application/json", strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == 409 {
			return nil, fmt.Errorf("名字已存在，请使用其他名字")
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("服务器返回错误: %s, 响应: %s", resp.Status, string(body))
	}

	// 解析响应
	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	encryptedResponse := response["info"]
	if encryptedResponse == "" {
		return nil, fmt.Errorf("响应中缺少info字段")
	}

	// 解密响应
	decrypted, err := decrypt(password, encryptedResponse)
	if err != nil {
		return nil, fmt.Errorf("解密响应失败: %w", err)
	}

	// 解析证书数据
	var certData CertResponse
	if err := json.Unmarshal([]byte(decrypted), &certData); err != nil {
		return nil, fmt.Errorf("解析证书数据失败: %w", err)
	}

	return &certData, nil
}

// 证书响应结构
type CertResponse struct {
	CA     string `json:"ca"`
	CRT    string `json:"crt"`
	KEY    string `json:"key"`
	Config string `json:"config"`
	IP     string `json:"ip"`
	Name   string `json:"name"`
}

// 保存证书文件
func saveCertFiles(data *CertResponse) error {
	// 保存ca.crt
	if err := os.WriteFile("./config/ca.crt", []byte(data.CA), 0644); err != nil {
		return err
	}

	// 保存客户端证书
	certPath := fmt.Sprintf("./config/%s.crt", data.Name)
	if err := os.WriteFile(certPath, []byte(data.CRT), 0644); err != nil {
		return err
	}

	// 保存客户端密钥
	keyPath := fmt.Sprintf("./config/%s.key", data.Name)
	if err := os.WriteFile(keyPath, []byte(data.KEY), 0644); err != nil {
		return err
	}

	// 保存配置文件
	if err := os.WriteFile("./config/config.yml", []byte(data.Config), 0644); err != nil {
		return err
	}

	// 创建用户数据库
	// 普通用户没有publicIP和password，所以传空字符串
	isAdmin := checkCertIsAdmin()
	if err := createUserDB(data.Name, data.IP, isAdmin, "", ""); err != nil {
		return fmt.Errorf("创建用户数据库失败: %w", err)
	}

	return nil
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
	// 回车，恢复终端状态，然后换行
	fmt.Print("\r")
	term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Print("\n")
	return string(password), nil
}

// 创建用户数据库
func createUserDB(userName, ip string, isAdmin bool, publicIP, password string) error {
	db, err := bolt.OpenDB("./config/data.db")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}
	defer db.Close()

	// 创建桶
	if err := bolt.CreateBucketIfNotExists(db, "metaDate"); err != nil {
		return fmt.Errorf("创建metaDate桶失败: %w", err)
	}
	if err := bolt.CreateBucketIfNotExists(db, "users"); err != nil {
		return fmt.Errorf("创建users桶失败: %w", err)
	}

	// 存储IP
	if err := bolt.PutKV(db, "metaDate", "ip", ip); err != nil {
		return fmt.Errorf("存储IP失败: %w", err)
	}

	// 存储用户名
	if err := bolt.PutKV(db, "metaDate", "name", userName); err != nil {
		return fmt.Errorf("存储用户名失败: %w", err)
	}

	// 存储管理员标志
	adminFlag := "false"
	if isAdmin {
		adminFlag = "true"
	}
	if err := bolt.PutKV(db, "metaDate", "is_admin", adminFlag); err != nil {
		return fmt.Errorf("存储管理员标志失败: %w", err)
	}

	// 如果是管理员，存储公网IP和密码
	if isAdmin {
		if publicIP != "" {
			if err := bolt.PutKV(db, "metaDate", "public_ip", publicIP); err != nil {
				return fmt.Errorf("存储公网IP失败: %w", err)
			}
		}
		if password != "" {
			if err := bolt.PutKV(db, "metaDate", "password", password); err != nil {
				return fmt.Errorf("存储密码失败: %w", err)
			}
		}
	}

	return nil
}
