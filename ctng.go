package main

import (
	"fmt"
	"os"
	"time"

	ca "github.com/jik18001/CTngV3/ca"
	def "github.com/jik18001/CTngV3/def"
	logger "github.com/jik18001/CTngV3/logger"
	monitor "github.com/jik18001/CTngV3/monitor"
)

const (
	cryptofile  = "def/testconfig.json"
	settingfile = "def/testsettings.json"
)

func main() {
	if len(os.Args) < 3 && os.Args[1] != "script-gen" {
		fmt.Println("Usage: go run ctng.go <CA|Logger|Monitor|script-gen> <CTngID>")
		os.Exit(1)
	}

	time.AfterFunc(2*time.Minute, func() {
		fmt.Println("Terminating the program after 2 minutes.")
		os.Exit(0)
	})

	// Initialize a new Setting object.
	restoredsetting := new(def.Settings)

	// Load the configuration from the file.
	def.LoadData(restoredsetting, settingfile)

	// Extract configuration values
	numFSMCAEEAs := restoredsetting.Num_CAs
	numFSMLoggerEEAs := restoredsetting.Num_Loggers
	numMonitors := restoredsetting.Num_Monitors

	fmt.Printf("Configuration Loaded: %d CA(s), %d Logger(s), %d Monitor(s)\n", numFSMCAEEAs, numFSMLoggerEEAs, numMonitors)

	switch os.Args[1] {
	case "CA":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		ca.StartCA(CTngID, cryptofile, settingfile)
	case "Logger":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		logger.StartLogger(CTngID, cryptofile, settingfile)
	case "Monitor":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		monitor.StartMonitorEEA(CTngID, cryptofile, settingfile)
	case "script-gen":
		err := generateScript(numFSMCAEEAs, numFSMLoggerEEAs, numMonitors)
		if err != nil {
			fmt.Printf("Failed to generate script: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Script generated successfully.")
	default:
		fmt.Println("Usage: go run ctng.go <CA|Logger|Monitor|script-gen> <CTngID>")
		os.Exit(1)
	}
}

func generateScript(numFSMCAEEAs, numFSMLoggerEEAs, numMonitors int) error {
	file, err := os.Create("network_script.sh")
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "#!/bin/bash")
	fmt.Fprintln(file, "SESSION=\"network\"\n")
	fmt.Fprintln(file, "# Start a new tmux session")
	fmt.Fprintln(file, "tmux new-session -d -s $SESSION\n")

	// Generate monitor windows
	for i := 1; i <= numMonitors; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_monitor_%d\" go run ctng.go Monitor M%d\n", i, i)
	}

	// Generate CA windows (commented out as in the example)
	for i := 1; i <= numFSMCAEEAs; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_ca_%d\" go run ctng.go CA C%d\n", i, i)
	}

	// Generate logger windows
	for i := 1; i <= numFSMLoggerEEAs; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_logger_%d\" go run ctng.go Logger L%d\n", i, i)
	}

	fmt.Fprintln(file, "\n# Attach to the tmux session")
	fmt.Fprintln(file, "tmux attach-session -t $SESSION")

	return nil
}
