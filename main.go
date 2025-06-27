package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ReconTool struct {
	Target    string
	Wordlist  string
	OutputDir string
	Logger    *log.Logger
	LogFile   *os.File
}

func NewReconTool(target, wordlist string) (*ReconTool, error) {
	timestamp := time.Now().Format("20060102_150405")
	outputDir := fmt.Sprintf("recon_%s_%s", strings.ReplaceAll(target, "/", "_"), timestamp)
	outputDir = strings.ReplaceAll(outputDir, ":", "_")

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("error creating directory: %v", err)
	}

	logPath := filepath.Join(outputDir, "recon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("error creating log file: %v", err)
	}

	logger := log.New(logFile, "", log.LstdFlags)

	return &ReconTool{
		Target:    target,
		Wordlist:  wordlist,
		OutputDir: outputDir,
		Logger:    logger,
		LogFile:   logFile,
	}, nil
}

func (r *ReconTool) Log(message string) {
	timestamp := time.Now().Format("15:04:05")
	logMsg := fmt.Sprintf("[%s] %s", timestamp, message)
	fmt.Println(logMsg)
	r.Logger.Println(message)
}

func (r *ReconTool) LogSilent(message string) {
	r.Logger.Println(message)
}

func (r *ReconTool) RunNmap(args []string, outputFile, description string) error {
	r.LogSilent("Starting: " + description)
	
	cmd := exec.Command("nmap")
	cmd.Args = append(cmd.Args, args...)
	cmd.Args = append(cmd.Args, r.Target)
	cmd.Args = append(cmd.Args, "-oN", filepath.Join(r.OutputDir, outputFile))
	cmd.Args = append(cmd.Args, "-oX", filepath.Join(r.OutputDir, outputFile+".xml"))

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nmap error: %v", err)
	}

	r.LogSilent("Completed: " + description)
	return nil
}

func (r *ReconTool) RunGobuster(url, outputFile string) error {
	r.LogSilent("Starting: Gobuster on " + url)
	
	// Check if wordlist exists
	if _, err := os.Stat(r.Wordlist); os.IsNotExist(err) {
		r.LogSilent("Warning: Wordlist not found at " + r.Wordlist + ", skipping gobuster")
		return nil
	}
	
	cmd := exec.Command("gobuster", "dir", "-u", url, "-w", r.Wordlist, "-o", filepath.Join(r.OutputDir, outputFile), "-q", "--timeout", "10s")
	err := cmd.Run()
	if err != nil {
		r.LogSilent("Gobuster error on " + url + ": " + err.Error())
		return nil // Don't fail the entire process for gobuster errors
	}

	r.LogSilent("Completed: Gobuster on " + url)
	return nil
}

func (r *ReconTool) ExtractOpenPorts(filename string) ([]string, error) {
	file, err := os.Open(filepath.Join(r.OutputDir, filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []string
	scanner := bufio.NewScanner(file)
	portRegex := regexp.MustCompile(`^(\d+)/tcp\s+open`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := portRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			ports = append(ports, matches[1])
		}
	}

	return ports, scanner.Err()
}

func (r *ReconTool) HasWebServices(filename string) ([]string, error) {
	file, err := os.Open(filepath.Join(r.OutputDir, filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var webUrls []string
	scanner := bufio.NewScanner(file)
	
	webPorts := map[string]string{
		"80":   "http",
		"443":  "https",
		"8080": "http",
		"8443": "https",
		"8008": "http",
		"8010": "http",
	}

	for scanner.Scan() {
		line := scanner.Text()
		for port, protocol := range webPorts {
			if strings.Contains(line, port+"/tcp") && strings.Contains(line, "open") {
				if port == "80" || port == "443" {
					webUrls = append(webUrls, fmt.Sprintf("%s://%s", protocol, r.Target))
				} else {
					webUrls = append(webUrls, fmt.Sprintf("%s://%s:%s", protocol, r.Target, port))
				}
			}
		}
	}

	return webUrls, scanner.Err()
}

func (r *ReconTool) RunRecon() error {
	defer r.LogFile.Close()

	r.Log("Reconnaissance started for " + r.Target)
	r.Log("Results in: " + r.OutputDir)

	// Phase 1: Initial scan
	r.Log("Phase 1: Initial scan of common ports")
	if err := r.RunNmap([]string{}, "01_initial_scan.txt", "Initial scan"); err != nil {
		return err
	}

	// Extract open ports
	openPorts, err := r.ExtractOpenPorts("01_initial_scan.txt")
	if err != nil {
		return fmt.Errorf("error extracting ports: %v", err)
	}

	if len(openPorts) == 0 {
		r.Log("No open ports found")
		return nil
	}

	r.Log("Open ports found: " + strings.Join(openPorts, ", "))

	var wg sync.WaitGroup

	// Phase 2: Detailed scan of found ports
	wg.Add(1)
	go func() {
		defer wg.Done()
		portList := strings.Join(openPorts, ",")
		r.RunNmap([]string{"-A", "-p", portList}, "02_detailed_scan.txt", "Detailed scan of ports "+portList)
	}()

	// Phase 3: Full port scan in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.RunNmap([]string{"-p-"}, "03_full_scan.txt", "Full port scan -p-")
	}()

	// Check for web services and launch gobuster
	webUrls, err := r.HasWebServices("01_initial_scan.txt")
	if err == nil && len(webUrls) > 0 {
		r.Log("Web services detected, starting gobuster")
		
		for _, url := range webUrls {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				safeName := strings.ReplaceAll(u, "://", "_")
				safeName = strings.ReplaceAll(safeName, ":", "_")
				safeName = strings.ReplaceAll(safeName, "/", "_")
				r.RunGobuster(u, "gobuster_"+safeName+".txt")
			}(url)
		}
	}

	r.Log("All scans running in background...")
	r.Log("You can continue using your terminal while scans complete.")
	r.Log("Check progress with: tail -f " + r.OutputDir + "/recon.log")
	fmt.Println()

	wg.Wait()

	// Phase 4: Final scan if new ports found
	allPorts, err := r.ExtractOpenPorts("03_full_scan.txt")
	if err == nil && len(allPorts) > len(openPorts) {
		r.Log("New ports found: " + strings.Join(allPorts, ", "))
		r.Log("Phase 4: Detailed scan of all ports")
		portList := strings.Join(allPorts, ",")
		r.RunNmap([]string{"-A", "-p", portList}, "04_final_detailed_scan.txt", "Final detailed scan")
	}

	r.Log("=== SUMMARY ===")
	r.Log("Open ports: " + strings.Join(openPorts, ", "))
	if len(allPorts) > len(openPorts) {
		r.Log("All ports: " + strings.Join(allPorts, ", "))
	}

	r.Log("🎯 Reconnaissance completed!")
	r.Log("📁 Results in: " + r.OutputDir)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: recon-tool <target> [wordlist]")
		fmt.Println("Example: recon-tool 10.10.10.1")
		fmt.Println("Example: recon-tool example.com /usr/share/wordlists/dirb/common.txt")
		os.Exit(1)
	}

	target := os.Args[1]
	wordlist := "/usr/share/wordlists/dirb/common.txt"
	
	if len(os.Args) > 2 {
		wordlist = os.Args[2]
	}

	tool, err := NewReconTool(target, wordlist)
	if err != nil {
		log.Fatal("Initialization error:", err)
	}

	if err := tool.RunRecon(); err != nil {
		log.Fatal("Reconnaissance error:", err)
	}
}