// v1.0.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexmullins/zip"
)

// 密码生成器结构
type PasswordGenerator struct {
	length       int
	useDigits    bool
	useLower     bool
	useUpper     bool
	useSpecial   bool
	specialChars string
	// 不确定的选项（'d'选项）
	unknownDigits  bool
	unknownLower   bool
	unknownUpper   bool
	unknownSpecial bool
}

// 从字典文件读取密码
func readDictionary(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}
	return passwords, scanner.Err()
}

// 随机打乱密码列表
func shufflePasswords(passwords []string) {
	rand.Seed(time.Now().UnixNano())
	for i := len(passwords) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		passwords[i], passwords[j] = passwords[j], passwords[i]
	}
}

// 生成字典密码的所有可能组合（截取不同位数）
// 生成字典词汇的所有子串组合
func generateAllSubstrings(passwords []string) []string {
	var variations []string
	seenPasswords := make(map[string]bool)

	for _, password := range passwords {
		// 生成所有可能的子串
		for i := 0; i < len(password); i++ {
			for j := i + 1; j <= len(password); j++ {
				substr := password[i:j]
				if len(substr) > 0 && !seenPasswords[substr] {
					variations = append(variations, substr)
					seenPasswords[substr] = true
				}
			}
		}
	}
	return variations
}

func generateDictVariations(passwords []string, targetLength int) []string {
	var variations []string
	seenPasswords := make(map[string]bool)

	for _, password := range passwords {
		// 如果密码长度大于等于目标长度，生成所有可能的截取组合
		if len(password) >= targetLength {
			for i := 0; i <= len(password)-targetLength; i++ {
				variation := password[i : i+targetLength]
				if !seenPasswords[variation] {
					variations = append(variations, variation)
					seenPasswords[variation] = true
				}
			}
		} else if len(password) == targetLength {
			// 如果密码长度正好等于目标长度
			if !seenPasswords[password] {
				variations = append(variations, password)
				seenPasswords[password] = true
			}
		}
	}
	return variations
}

// 生成暴力破解密码
func (pg *PasswordGenerator) generatePasswords() <-chan string {
	ch := make(chan string, 1000)
	go func() {
		defer close(ch)

		// 检查是否有不确定的选项
		if pg.unknownDigits || pg.unknownLower || pg.unknownUpper || pg.unknownSpecial {
			// 生成所有可能的字符集组合
			pg.generateAllCharsetCombinations(ch)
		} else {
			// 原有逻辑：单一字符集
			pg.generateSingleCharset(ch)
		}
	}()
	return ch
}

// 生成单一字符集的密码（原有逻辑）
func (pg *PasswordGenerator) generateSingleCharset(ch chan<- string) {
	var charset string
	if pg.useDigits {
		charset += "0123456789"
	}
	if pg.useLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if pg.useUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if pg.useSpecial {
		charset += pg.specialChars
	}

	if charset == "" {
		return
	}

	// 生成所有可能的密码组合
	if pg.length == 0 {
		// 默认情况：生成1到10位的所有组合
		for length := 1; length <= 10; length++ {
			pg.generateCombinations(charset, "", length, ch)
		}
	} else {
		// 指定长度
		pg.generateCombinations(charset, "", pg.length, ch)
	}
}

// 生成所有可能的字符集组合（处理不确定选项）
func (pg *PasswordGenerator) generateAllCharsetCombinations(ch chan<- string) {
	// 计算所有可能的组合数量
	digitsOptions := []bool{false}
	lowerOptions := []bool{false}
	upperOptions := []bool{false}
	specialOptions := []bool{false}

	if pg.unknownDigits {
		digitsOptions = []bool{false, true}
	} else {
		digitsOptions = []bool{pg.useDigits}
	}

	if pg.unknownLower {
		lowerOptions = []bool{false, true}
	} else {
		lowerOptions = []bool{pg.useLower}
	}

	if pg.unknownUpper {
		upperOptions = []bool{false, true}
	} else {
		upperOptions = []bool{pg.useUpper}
	}

	if pg.unknownSpecial {
		specialOptions = []bool{false, true}
	} else {
		specialOptions = []bool{pg.useSpecial}
	}

	// 遍历所有组合
	for _, useDigits := range digitsOptions {
		for _, useLower := range lowerOptions {
			for _, useUpper := range upperOptions {
				for _, useSpecial := range specialOptions {
					// 构建当前组合的字符集
					var charset string
					if useDigits {
						charset += "0123456789"
					}
					if useLower {
						charset += "abcdefghijklmnopqrstuvwxyz"
					}
					if useUpper {
						charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					}
					if useSpecial {
						charset += pg.specialChars
					}

					// 跳过空字符集
					if charset == "" {
						continue
					}

					// 生成当前字符集的所有密码
					if pg.length == 0 {
						// 默认情况：生成1到10位的所有组合
						for length := 1; length <= 10; length++ {
							pg.generateCombinations(charset, "", length, ch)
						}
					} else {
						// 指定长度
						pg.generateCombinations(charset, "", pg.length, ch)
					}
				}
			}
		}
	}
}

// 递归生成密码组合
func (pg *PasswordGenerator) generateCombinations(charset, current string, remaining int, ch chan<- string) {
	if remaining == 0 {
		ch <- current
		return
	}

	for _, char := range charset {
		pg.generateCombinations(charset, current+string(char), remaining-1, ch)
	}
}

// 计算可能的密码数量
func (pg *PasswordGenerator) calculatePossibilities() int64 {
	// 检查是否有不确定的选项
	if pg.unknownDigits || pg.unknownLower || pg.unknownUpper || pg.unknownSpecial {
		return pg.calculateAllCharsetCombinationsPossibilities()
	} else {
		return pg.calculateSingleCharsetPossibilities()
	}
}

// 计算单一字符集的可能性数量（原有逻辑）
func (pg *PasswordGenerator) calculateSingleCharsetPossibilities() int64 {
	var charsetSize int
	if pg.useDigits {
		charsetSize += 10
	}
	if pg.useLower {
		charsetSize += 26
	}
	if pg.useUpper {
		charsetSize += 26
	}
	if pg.useSpecial {
		charsetSize += len(pg.specialChars)
	}

	if charsetSize == 0 {
		return 0
	}

	if pg.length == 0 {
		// 默认情况：计算1到10位的总可能数
		totalResult := 0.0
		for length := 1; length <= 10; length++ {
			lengthResult := 1.0
			for i := 0; i < length; i++ {
				lengthResult *= float64(charsetSize)
				// 如果单个长度的结果超过int64最大值，返回最大值
				if lengthResult > 9223372036854775807 {
					return 9223372036854775807 // int64最大值
				}
			}
			totalResult += lengthResult
			// 如果总结果超过int64最大值，返回最大值
			if totalResult > 9223372036854775807 {
				return 9223372036854775807 // int64最大值
			}
		}
		return int64(totalResult)
	} else {
		// 指定长度的计算
		result := 1.0
		for i := 0; i < pg.length; i++ {
			result *= float64(charsetSize)
			// 如果结果超过int64最大值，返回最大值
			if result > 9223372036854775807 {
				return 9223372036854775807 // int64最大值
			}
		}
		return int64(result)
	}
}

// 计算所有字符集组合的可能性数量（处理不确定选项）
func (pg *PasswordGenerator) calculateAllCharsetCombinationsPossibilities() int64 {
	// 计算所有可能的组合数量
	digitsOptions := []bool{false}
	lowerOptions := []bool{false}
	upperOptions := []bool{false}
	specialOptions := []bool{false}

	if pg.unknownDigits {
		digitsOptions = []bool{false, true}
	} else {
		digitsOptions = []bool{pg.useDigits}
	}

	if pg.unknownLower {
		lowerOptions = []bool{false, true}
	} else {
		lowerOptions = []bool{pg.useLower}
	}

	if pg.unknownUpper {
		upperOptions = []bool{false, true}
	} else {
		upperOptions = []bool{pg.useUpper}
	}

	if pg.unknownSpecial {
		specialOptions = []bool{false, true}
	} else {
		specialOptions = []bool{pg.useSpecial}
	}

	totalPossibilities := 0.0

	// 遍历所有组合
	for _, useDigits := range digitsOptions {
		for _, useLower := range lowerOptions {
			for _, useUpper := range upperOptions {
				for _, useSpecial := range specialOptions {
					// 计算当前组合的字符集大小
					var charsetSize int
					if useDigits {
						charsetSize += 10
					}
					if useLower {
						charsetSize += 26
					}
					if useUpper {
						charsetSize += 26
					}
					if useSpecial {
						charsetSize += len(pg.specialChars)
					}

					// 跳过空字符集
					if charsetSize == 0 {
						continue
					}

					// 计算当前字符集的可能性
					if pg.length == 0 {
						// 默认情况：计算1到10位的总可能数
						for length := 1; length <= 10; length++ {
							lengthResult := 1.0
							for i := 0; i < length; i++ {
								lengthResult *= float64(charsetSize)
								// 防止溢出
								if lengthResult > 9223372036854775807 {
									return 9223372036854775807
								}
							}
							totalPossibilities += lengthResult
							// 防止溢出
							if totalPossibilities > 9223372036854775807 {
								return 9223372036854775807
							}
						}
					} else {
						// 指定长度的计算
						result := 1.0
						for i := 0; i < pg.length; i++ {
							result *= float64(charsetSize)
							// 防止溢出
							if result > 9223372036854775807 {
								return 9223372036854775807
							}
						}
						totalPossibilities += result
						// 防止溢出
						if totalPossibilities > 9223372036854775807 {
							return 9223372036854775807
						}
					}
				}
			}
		}
	}

	return int64(totalPossibilities)
}

// 显示进度条
func showProgress(current, total int64, startTime time.Time) {
	if total == 0 {
		return
	}

	elapsed := time.Since(startTime)
	rate := float64(current) / elapsed.Seconds()

	// 计算最长耗时（完成所有可能性所需的时间）
	maxTime := time.Duration(0)
	if rate > 0 {
		maxTime = time.Duration(float64(total)/rate) * time.Second
	}

	// 按指定格式输出
	fmt.Printf("- %d/%d | 速度: %.0f条/s | %v/%v\n",
		current, total, rate, elapsed, maxTime)
}

// 显示简单进度信息（当总数未知时）
func showSimpleProgress(current int64, startTime time.Time) {
	elapsed := time.Since(startTime)
	rate := float64(current) / elapsed.Seconds()

	// 按指定格式输出（总数未知时显示为未知）
	fmt.Printf("- %d/未知 | 速度: %.0f条/s | %v/未知\n", current, rate, elapsed)
}

// 检查ZIP文件是否加密
func isZipEncrypted(zipPath string) bool {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return false
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.IsEncrypted() {
			return true
		}
	}
	return false
}

// 尝试解压ZIP文件
func tryPassword(zipPath, password string) bool {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return false
	}
	defer reader.Close()

	// 检查是否有加密文件
	hasEncryptedFile := false
	for _, file := range reader.File {
		if file.IsEncrypted() {
			hasEncryptedFile = true
			file.SetPassword(password)
			rc, err := file.Open()
			if err != nil {
				return false
			}
			// 尝试读取一些数据来验证密码
			buf := make([]byte, 10)
			_, err = rc.Read(buf)
			rc.Close()
			if err != nil && err != io.EOF {
				return false
			}
			// 如果能成功读取，说明密码正确
			return true
		}
	}

	// 如果没有加密文件，返回false
	if !hasEncryptedFile {
		fmt.Println("警告：ZIP文件似乎没有加密")
		return false
	}

	return false
}

// 多线程密码尝试
// 带进度显示的多线程密码尝试
func tryPasswordsConcurrentWithProgress(zipPath string, passwords []string, numWorkers int, startTime time.Time) (string, bool, int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	passwordChan := make(chan string, len(passwords))
	resultChan := make(chan string, 1)
	progressChan := make(chan int, numWorkers*2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var triedCount int
	totalPasswords := len(passwords)

	// 启动工作协程
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localCount := 0
			for {
				select {
				case <-ctx.Done():
					if localCount > 0 {
						progressChan <- localCount
					}
					return
				case password, ok := <-passwordChan:
					if !ok {
						if localCount > 0 {
							progressChan <- localCount
						}
						return
					}
					localCount++
					if tryPassword(zipPath, password) {
						progressChan <- localCount
						select {
						case resultChan <- password:
							cancel() // 取消所有其他协程
						default:
						}
						return
					}
					if localCount%1000 == 0 {
						progressChan <- localCount
						localCount = 0
					}
				}
			}
		}()
	}

	// 进度统计和显示协程
	go func() {
		for count := range progressChan {
			mu.Lock()
			triedCount += count
			currentCount := triedCount
			mu.Unlock()

			// 显示进度
			if totalPasswords > 0 {
				showProgress(int64(currentCount), int64(totalPasswords), startTime)
			} else {
				showSimpleProgress(int64(currentCount), startTime)
			}
		}
	}()

	// 发送密码到通道
	go func() {
		for _, password := range passwords {
			passwordChan <- password
		}
		close(passwordChan)
	}()

	// 等待结果或所有工作完成
	go func() {
		wg.Wait()
		close(progressChan)
		close(resultChan)
	}()

	if result := <-resultChan; result != "" {
		mu.Lock()
		finalCount := triedCount
		mu.Unlock()
		return result, true, finalCount
	}
	mu.Lock()
	finalCount := triedCount
	mu.Unlock()
	return "", false, finalCount
}

func tryPasswordsConcurrent(zipPath string, passwords []string, numWorkers int) (string, bool, int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	passwordChan := make(chan string, len(passwords))
	resultChan := make(chan string, 1)
	progressChan := make(chan int, numWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var triedCount int

	// 启动工作协程
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localCount := 0
			for {
				select {
				case <-ctx.Done():
					if localCount > 0 {
						progressChan <- localCount
					}
					return
				case password, ok := <-passwordChan:
					if !ok {
						if localCount > 0 {
							progressChan <- localCount
						}
						return
					}
					localCount++
					if tryPassword(zipPath, password) {
						progressChan <- localCount
						select {
						case resultChan <- password:
							cancel() // 取消所有其他协程
						default:
						}
						return
					}
					if localCount%1000 == 0 {
						progressChan <- localCount
						localCount = 0
					}
				}
			}
		}()
	}

	// 进度统计协程
	go func() {
		for count := range progressChan {
			mu.Lock()
			triedCount += count
			mu.Unlock()
		}
	}()

	// 发送密码到通道
	go func() {
		for _, password := range passwords {
			passwordChan <- password
		}
		close(passwordChan)
	}()

	// 等待结果或所有工作完成
	go func() {
		wg.Wait()
		close(progressChan)
		close(resultChan)
	}()

	if result := <-resultChan; result != "" {
		mu.Lock()
		finalCount := triedCount
		mu.Unlock()
		return result, true, finalCount
	}
	mu.Lock()
	finalCount := triedCount
	mu.Unlock()
	return "", false, finalCount
}

// 等待用户按键退出
func waitForUserExit() {
	fmt.Println("\n按回车键退出程序...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

// 用户交互函数
// 获取密码设置（用于拖拽文件模式）
func getPasswordSettings() (*PasswordGenerator, bool) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n=== ZIP压缩包暴力破解工具 ===")
	fmt.Println("注意：本工具仅用于学习目的，请勿用于非法用途！")
	fmt.Println()

	// 询问是否知道密码范围
	fmt.Println("您是否知道密码的大致范围？")
	fmt.Println("a) 是的，我知道一些信息")
	fmt.Println("b) 不知道，直接使用字典攻击")
	fmt.Print("请选择 (a/b): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))

	if choice == "b" {
		return nil, true // 使用字典攻击
	}

	// 获取密码详细信息
	pg := &PasswordGenerator{
		specialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?",
	}

	// 询问密码长度（带输入验证和默认值）
	for {
		fmt.Print("\n密码长度是多少位？(输入数字，默认d=1到10位): ")
		lengthStr, _ := reader.ReadString('\n')
		lengthStr = strings.TrimSpace(lengthStr)

		// 默认值处理
		if lengthStr == "" || lengthStr == "d" {
			pg.length = 0 // 0表示使用1-10位范围
			break
		}

		length, err := strconv.Atoi(lengthStr)
		if err != nil || length <= 0 || length > 20 {
			fmt.Println("- 输入错误！请输入1-20之间的数字，或按回车使用默认值")
		} else {
			pg.length = length
			break
		}
	}

	// 询问字符类型（带输入验证和默认值）

	// 数字
	for {
		fmt.Print("\n密码是否包含数字？(y/n/d=不知道，默认y): ")
		digits, _ := reader.ReadString('\n')
		digits = strings.TrimSpace(strings.ToLower(digits))

		if digits == "" {
			digits = "y" // 默认值
		}

		if digits == "y" || digits == "n" || digits == "d" {
			if digits == "d" {
				pg.unknownDigits = true
				pg.useDigits = false // 临时设为false，后续会生成所有组合
			} else {
				pg.unknownDigits = false
				pg.useDigits = digits == "y"
			}
			break
		} else {
			fmt.Println("- 输入错误！请输入 'y'、'n' 或 'd'")
		}
	}

	// 小写字母
	for {
		fmt.Print("密码是否包含小写字母？(y/n/d=不知道，默认y): ")
		lower, _ := reader.ReadString('\n')
		lower = strings.TrimSpace(strings.ToLower(lower))

		if lower == "" {
			lower = "y" // 默认值
		}

		if lower == "y" || lower == "n" || lower == "d" {
			if lower == "d" {
				pg.unknownLower = true
				pg.useLower = false
			} else {
				pg.unknownLower = false
				pg.useLower = lower == "y"
			}
			break
		} else {
			fmt.Println("- 输入错误！请输入 'y'、'n' 或 'd'")
		}
	}

	// 大写字母
	for {
		fmt.Print("密码是否包含大写字母？(y/n/d=不知道，默认y): ")
		upper, _ := reader.ReadString('\n')
		upper = strings.TrimSpace(strings.ToLower(upper))

		if upper == "" {
			upper = "y" // 默认值
		}

		if upper == "y" || upper == "n" || upper == "d" {
			if upper == "d" {
				pg.unknownUpper = true
				pg.useUpper = false
			} else {
				pg.unknownUpper = false
				pg.useUpper = upper == "y"
			}
			break
		} else {
			fmt.Println("- 输入错误！请输入 'y'、'n' 或 'd'")
		}
	}

	// 特殊符号
	for {
		fmt.Print("密码是否包含特殊符号？(y/n/d=不知道，默认n): ")
		special, _ := reader.ReadString('\n')
		special = strings.TrimSpace(strings.ToLower(special))

		if special == "" {
			special = "n" // 默认值
		}

		if special == "y" || special == "n" || special == "d" {
			if special == "d" {
				pg.unknownSpecial = true
				pg.useSpecial = false
			} else {
				pg.unknownSpecial = false
				pg.useSpecial = special == "y"
			}
			break
		} else {
			fmt.Println("- 输入错误！请输入 'y'、'n' 或 'd'")
		}
	}

	// 显示配置总结并提醒用户检查
	fmt.Println("\n- 让我们来看看您的配置：")
	fmt.Printf("密码长度: %d 位\n", pg.length)
	fmt.Printf("包含数字: %v\n", pg.useDigits)
	fmt.Printf("包含小写字母: %v\n", pg.useLower)
	fmt.Printf("包含大写字母: %v\n", pg.useUpper)
	fmt.Printf("包含特殊符号: %v\n", pg.useSpecial)

	fmt.Println("\n- 温馨提示：请仔细检查上述配置是否正确！")
	fmt.Println("如果设置错误，可能会导致您的密码永远也破解不了...")
	fmt.Println("就像用钥匙开锁，如果钥匙型号都不对，那就只能「望门兴叹」了！")
	fmt.Print("\n确认配置无误，开始破解？(y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" {
		fmt.Println("明智的选择！重新配置总比白忙活强~")
		return getPasswordSettings() // 递归调用重新设置
	}

	return pg, false
}

func getUserInput() (*PasswordGenerator, string, bool) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== ZIP压缩包暴力破解工具 ===")
	fmt.Println("注意：本工具仅用于学习目的，请勿用于非法用途！")
	fmt.Println()

	// 获取ZIP文件路径
	fmt.Print("请输入ZIP文件路径: ")
	zipPath, _ := reader.ReadString('\n')
	zipPath = strings.TrimSpace(zipPath)

	// 验证ZIP文件路径
	if zipPath == "" {
		fmt.Println("错误：ZIP文件路径不能为空！")
		fmt.Println("程序退出，请重新运行并输入正确的文件路径。")
		os.Exit(1)
	}

	// 检查文件是否存在
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		fmt.Printf("- 错误：文件 '%s' 不存在！\n", zipPath)
		fmt.Println("程序退出，请检查文件路径是否正确。")
		os.Exit(1)
	}

	// 询问是否知道密码范围（带输入验证和默认值）
	for {
		fmt.Println("\n您是否知道密码的大致范围？")
		fmt.Println("a) 是的，我知道一些信息")
		fmt.Println("b) 不知道，直接使用字典攻击")
		fmt.Print("请选择 (a/b，默认b): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		// 默认值处理
		if choice == "" {
			choice = "b"
		}

		if choice == "a" || choice == "b" {
			if choice == "b" {
				return nil, zipPath, true // 使用字典攻击
			}
			break
		} else {
			fmt.Println("- 输入错误！请输入 'a' 或 'b'")
		}
	}

	// 获取密码详细信息
	pg := &PasswordGenerator{
		specialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?",
	}

	// 询问密码长度
	fmt.Print("\n密码长度是多少位？(输入数字，如果不知道请输入 d): ")
	lengthStr, _ := reader.ReadString('\n')
	lengthStr = strings.TrimSpace(lengthStr)
	if lengthStr == "d" {
		pg.length = 8 // 默认长度
	} else {
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length <= 0 {
			fmt.Println("无效输入，使用默认长度8")
			pg.length = 8
		} else {
			pg.length = length
		}
	}

	// 询问字符类型
	fmt.Print("\n密码是否包含数字？(y/n/d): ")
	digits, _ := reader.ReadString('\n')
	digits = strings.TrimSpace(strings.ToLower(digits))
	pg.useDigits = digits == "y" || digits == "d"

	fmt.Print("密码是否包含小写字母？(y/n/d): ")
	lower, _ := reader.ReadString('\n')
	lower = strings.TrimSpace(strings.ToLower(lower))
	pg.useLower = lower == "y" || lower == "d"

	fmt.Print("密码是否包含大写字母？(y/n/d): ")
	upper, _ := reader.ReadString('\n')
	upper = strings.TrimSpace(strings.ToLower(upper))
	pg.useUpper = upper == "y" || upper == "d"

	fmt.Print("密码是否包含特殊符号？(y/n/d): ")
	special, _ := reader.ReadString('\n')
	special = strings.TrimSpace(strings.ToLower(special))
	pg.useSpecial = special == "y"

	return pg, zipPath, false
}

func main() {
	// 检查命令行参数（支持拖拽文件到exe上）
	var zipPath string
	if len(os.Args) > 1 {
		// 从命令行参数获取ZIP文件路径
		zipPath = os.Args[1]
		fmt.Printf("检测到拖拽文件: %s\n", zipPath)
	} else {
		// 交互式获取ZIP文件路径
		pg, inputZipPath, useDictOnly := getUserInput()
		zipPath = inputZipPath

		// 检查ZIP文件是否存在
		if _, err := os.Stat(zipPath); os.IsNotExist(err) {
			fmt.Printf("错误：文件 %s 不存在\n", zipPath)
			waitForUserExit()
			return
		}

		// 执行破解逻辑
		executeCracking(pg, zipPath, useDictOnly)
		return
	}

	// 检查拖拽的ZIP文件是否存在
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		fmt.Printf("错误：文件 %s 不存在\n", zipPath)
		waitForUserExit()
		return
	}

	// 对于拖拽的文件，询问破解模式
	pg, useDictOnly := getPasswordSettings()

	// 执行破解逻辑
	executeCracking(pg, zipPath, useDictOnly)
}

// 执行破解逻辑
func executeCracking(pg *PasswordGenerator, zipPath string, useDictOnly bool) {
	var found bool
	var correctPassword string
	startTime := time.Now()
	triedCount := 0
	numWorkers := 4 // 使用4个工作线程

	// 读取字典文件
	dictPath := "data/dic/weak.txt"
	passwords, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("警告：无法读取字典文件 %s: %v\n", dictPath, err)
		passwords = []string{}
	}

	if useDictOnly {
		// 先进行完整字典攻击
		fmt.Printf("\n开始字典攻击，共 %d 个密码...\n", len(passwords))
		fmt.Println("正在随机打乱字典顺序以提高破解效率...")
		shufflePasswords(passwords)

		// 多线程字典攻击
		result, success, count := tryPasswordsConcurrentWithProgress(zipPath, passwords, numWorkers, startTime)
		triedCount += count
		if success {
			correctPassword = result
			found = true
		} else {
			// 生成所有子串组合进行攻击
			fmt.Println("\n完整字典攻击未找到密码，开始子串组合攻击...")
			substringPasswords := generateAllSubstrings(passwords)
			fmt.Printf("生成子串组合共 %d 个密码\n", len(substringPasswords))
			fmt.Println("正在随机打乱子串顺序...")
			shufflePasswords(substringPasswords)
			
			// 多线程子串攻击
			result, success, count = tryPasswordsConcurrentWithProgress(zipPath, substringPasswords, numWorkers, startTime)
			triedCount += count
			if success {
				correctPassword = result
				found = true
			} else {
				// 子串攻击也失败，询问是否进行暴力破解
				fmt.Println("\n子串组合攻击也未找到密码。")
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("是否继续进行暴力破解？(y/n，默认n): ")
				continueChoice, _ := reader.ReadString('\n')
				continueChoice = strings.TrimSpace(strings.ToLower(continueChoice))
				if continueChoice == "y" {
					// 转为暴力破解模式
					useDictOnly = false
					fmt.Println("\n开始暴力破解模式...")
				}
			}
		}
	}
	
	if !useDictOnly && !found {
		// 计算可能的密码数量
		possibilities := pg.calculatePossibilities()
		fmt.Printf("\n根据您的设置，可能的密码组合数: %d\n", possibilities)

		// 检查是否超过1亿条，给出警告
		if possibilities > 100000000 { // 1亿
			fmt.Println("\n- 哇哦！密码可能性超过1亿条！")
			fmt.Println("这就像在茫茫人海中寻找一个特定的人...")
			fmt.Println("强行破解的成功率比中彩票还低，主要靠运气和人品！")
			fmt.Println("建议您：")
			fmt.Println("  1. 重新思考密码设置，缩小范围")
			fmt.Println("  2. 或者准备好泡杯茶，慢慢等...")
			fmt.Println("  3. 也可以去买张彩票，说不定更快中奖")

			reader := bufio.NewReader(os.Stdin)
			fmt.Print("\n您确定要继续这场'不可能的任务'吗？(y/n): ")
			continueChoice, _ := reader.ReadString('\n')
			continueChoice = strings.TrimSpace(strings.ToLower(continueChoice))
			if continueChoice != "y" {
				fmt.Println("明智的选择！有时候战略性撤退比硬刚更聪明~")
				return
			}
			fmt.Println("\n好吧，既然您坚持，那就开始这场马拉松式的破解之旅吧！")
		}

		// 决定是否使用字典
		if possibilities >= 10000 {
			fmt.Println("密码可能性较多，先尝试字典攻击...")

			// 生成字典变体
			dictVariations := generateDictVariations(passwords, pg.length)
			fmt.Printf("字典变体共 %d 个密码\n", len(dictVariations))
			fmt.Println("正在随机打乱字典顺序...")
			shufflePasswords(dictVariations)

			// 多线程字典攻击
			result, success, count := tryPasswordsConcurrentWithProgress(zipPath, dictVariations, numWorkers, startTime)
			triedCount += count
			if success {
				correctPassword = result
				found = true
			}
		}

		// 如果字典攻击失败，进行暴力破解
		if !found {
			fmt.Println("\n字典攻击失败，开始暴力破解...")
			passwordChan := pg.generatePasswords()

			// 分批处理暴力破解密码
			var passwords []string
			for password := range passwordChan {
				passwords = append(passwords, password)
				if len(passwords) >= 10000 { // 分批处理，避免内存占用过大
					result, success, count := tryPasswordsConcurrent(zipPath, passwords, numWorkers)
					triedCount += count
					if success {
						correctPassword = result
						found = true
						break
					}
					passwords = passwords[:0] // 清空切片
					// 使用showProgress显示准确的进度，包含总可能性数量
					showProgress(int64(triedCount), possibilities, startTime)
				}
			}
			// 处理剩余密码
			if !found && len(passwords) > 0 {
				result, success, count := tryPasswordsConcurrent(zipPath, passwords, numWorkers)
				triedCount += count
				if success {
					correctPassword = result
					found = true
				}
			}
		}
	}

	elapsedTime := time.Since(startTime)

	if found {
		fmt.Printf("\n\no 密码破解成功！\n")
		fmt.Printf("密码: %s\n", correctPassword)
		fmt.Printf("尝试次数: %d\n", triedCount)
		fmt.Printf("耗时: %v\n", elapsedTime)
		waitForUserExit()
	} else {
		fmt.Printf("\n\nx 密码破解失败\n")
		fmt.Printf("尝试次数: %d\n", triedCount)
		fmt.Printf("耗时: %v\n", elapsedTime)
		fmt.Println("建议：尝试扩大密码范围或使用更完整的字典")
		waitForUserExit()
	}
}
