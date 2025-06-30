package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"hllprepen/scanner"
)

func main() {
	showWelcome()
	scanner.Init()
}

func showWelcome() {
	logo, err := os.ReadFile("assets/logo.txt")
	if err == nil {
		fmt.Println(string(logo))
	} else {
		// Fallback logo
		fmt.Println(`
██╗  ██╗██╗     ██╗     	██████╗ ██████╗ ███████╗	██████╗ ███████╗███╗   ██╗
██║  ██║██║     ██║     	██╔══██╗██╔══██╗██╔════╝	██╔══██╗██╔════╝████╗  ██║
███████║██║     ██║     	██████╔╝██████╔╝█████╗  	██████╔╝█████╗  ██╔██╗ ██║
██╔══██║██║     ██║     	██╔═══╝ ██╔══██╗██╔══╝  	██╔═══╝ ██╔══╝  ██║╚██╗██║
██║  ██║███████╗███████╗	██║     ██║  ██║███████╗	██║     ███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝╚══════╝	╚═╝     ╚═╝  ╚═╝╚══════╝	╚═╝     ╚══════╝╚═╝  ╚═══╝
`)
	}
	fmt.Println("Hoşgeldin! Pre-Pen Test Aracı için işlem seçer misin:")
	fmt.Println("[1] Yeni Test Başlat")
	fmt.Println("[2] Çıkış")
	fmt.Print("Seçimin: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		scanner.StartInteractiveSession()
	default:
		fmt.Println("Kapanıyor...")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}
}
