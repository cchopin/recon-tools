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
		return nil, fmt.Errorf("erreur création dossier: %v", err)
	}

	logPath := filepath.Join(outputDir, "recon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("erreur création log: %v", err)
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

func (r *ReconTool) RunNmap(args []string, outputFile, description string) error {
	r.Log("Démarrage: " + description)
	
	cmd := exec.Command("nmap")
	cmd.Args = append(cmd.Args, args...)
	cmd.Args = append(cmd.Args, r.Target)
	cmd.Args = append(cmd.Args, "-oN", filepath.Join(r.OutputDir, outputFile))
	cmd.Args = append(cmd.Args, "-oX", filepath.Join(r.OutputDir, outputFile+".xml"))

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("erreur nmap: %v", err)
	}

	r.Log("Terminé: " + description)
	return nil
}

func (r *ReconTool) RunGobuster(url, outputFile string) error {
	r.Log("Démarrage: Gobuster sur " + url)
	
	cmd := exec.Command("gobuster", "dir", "-u", url, "-w", r.Wordlist, "-o", filepath.Join(r.OutputDir, outputFile), "-q")
	err := cmd.Run()
	if err != nil {
		r.Log("Erreur gobuster sur " + url + ": " + err.Error())
		return err
	}

	r.Log("Terminé: Gobuster sur " + url)
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

	r.Log("Reconnaissance démarrée pour " + r.Target)
	r.Log("Résultats dans: " + r.OutputDir)

	// Phase 1: Scan initial
	r.Log("Phase 1: Scan initial des ports courants")
	if err := r.RunNmap([]string{}, "01_initial_scan.txt", "Scan initial"); err != nil {
		return err
	}

	// Extraire les ports ouverts
	openPorts, err := r.ExtractOpenPorts("01_initial_scan.txt")
	if err != nil {
		return fmt.Errorf("erreur extraction ports: %v", err)
	}

	if len(openPorts) == 0 {
		r.Log("Aucun port ouvert trouvé")
		return nil
	}

	r.Log("Ports ouverts trouvés: " + strings.Join(openPorts, ", "))

	var wg sync.WaitGroup

	// Phase 2: Scan détaillé des ports trouvés
	wg.Add(1)
	go func() {
		defer wg.Done()
		portList := strings.Join(openPorts, ",")
		r.RunNmap([]string{"-A", "-p", portList}, "02_detailed_scan.txt", "Scan détaillé des ports "+portList)
	}()

	// Phase 3: Scan complet en parallèle
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.RunNmap([]string{"-p-"}, "03_full_scan.txt", "Scan complet -p-")
	}()

	// Vérifier les services web et lancer gobuster
	webUrls, err := r.HasWebServices("01_initial_scan.txt")
	if err == nil && len(webUrls) > 0 {
		r.Log("Services web détectés, démarrage de gobuster")
		
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

	wg.Wait()

	// Phase 4: Scan final si nouveaux ports trouvés
	allPorts, err := r.ExtractOpenPorts("03_full_scan.txt")
	if err == nil && len(allPorts) > len(openPorts) {
		r.Log("Nouveaux ports trouvés: " + strings.Join(allPorts, ", "))
		r.Log("Phase 4: Scan détaillé de tous les ports")
		portList := strings.Join(allPorts, ",")
		r.RunNmap([]string{"-A", "-p", portList}, "04_final_detailed_scan.txt", "Scan détaillé final")
	}

	r.Log("=== RÉSUMÉ ===")
	r.Log("Ports ouverts: " + strings.Join(openPorts, ", "))
	if len(allPorts) > len(openPorts) {
		r.Log("Tous les ports: " + strings.Join(allPorts, ", "))
	}

	r.Log("🎯 Reconnaissance terminée!")
	r.Log("📁 Résultats dans: " + r.OutputDir)
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
		log.Fatal("Erreur initialisation:", err)
	}

	if err := tool.RunRecon(); err != nil {
		log.Fatal("Erreur reconnaissance:", err)
	}
}