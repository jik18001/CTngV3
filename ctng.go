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

func main() {
	if len(os.Args) < 4 && os.Args[1] != "Script" {
		fmt.Println("Usage: go run ctng.go <CA|Logger|Monitor|Script> <CTngID> <local|deter>")
		os.Exit(1)
	}

	var cryptofile = "def/testconfig.json"
	var settingfile = "def/testsettings.json"
	if os.Args[3] == "deter" {
		cryptofile = "deter/deterconfig.json"
		settingfile = "deter/detersettings.json"
	}

	// Initialize a new Setting object.
	restoredsetting := new(def.Settings)

	// Load the configuration from the file.
	def.LoadData(restoredsetting, settingfile)

	// Extract configuration values
	numFSMCAEEAs := restoredsetting.Num_CAs
	numFSMLoggerEEAs := restoredsetting.Num_Loggers
	numMonitors := restoredsetting.Num_Monitors
	MUD := restoredsetting.MUD
	time.AfterFunc(time.Duration(MUD)*time.Second, func() {
		fmt.Println("Terminating the program after MUD.")
		os.Exit(0)
	})

	fmt.Printf("Configuration Loaded: %d CA(s), %d Logger(s), %d Monitor(s)\n", numFSMCAEEAs, numFSMLoggerEEAs, numMonitors)

	switch os.Args[1] {
	case "CA":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		ca.StartCA(CTngID, cryptofile, settingfile)
	case "CAD":
		ca.StartCADeter(cryptofile, settingfile)
	case "Logger":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		logger.StartLogger(CTngID, cryptofile, settingfile)
	case "Monitor":
		CTngID := def.CTngID(os.Args[2])
		fmt.Println(CTngID)
		monitor.StartMonitor(CTngID, cryptofile, settingfile)
	case "Script":
		err := generateScript(numFSMCAEEAs, numFSMLoggerEEAs, numMonitors)
		if err != nil {
			fmt.Printf("Failed to generate script: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Script generated successfully.")
	default:
		fmt.Println("Usage: go run ctng.go <CA|Logger|Monitor|Script> <CTngID>")
		os.Exit(1)
	}
}

func generateScript(numFSMCAEEAs, numFSMLoggerEEAs, numMonitors int) error {
	file, err := os.Create("run.sh")
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "#!/bin/bash")
	fmt.Fprintln(file, "SESSION=\"network\"\n")
	fmt.Fprintln(file, "# Start a new tmux session")
	fmt.Fprintln(file, "tmux new-session -d -s $SESSION\n")

	// Generate monitor windows with race condition detection and redirection to log files
	for i := 1; i <= numMonitors; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_monitor_%d\" bash -c 'go run -race ctng.go Monitor M%d > monitor_%d.log 2>&1'\n", i, i, i)
	}

	// Add a 1-second delay after starting all the monitors
	fmt.Fprintln(file, "sleep 1\n")

	// Generate CA windows with race condition detection and redirection to log files
	for i := 1; i <= numFSMCAEEAs; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_ca_%d\" bash -c 'go run -race ctng.go CA C%d > ca_%d.log 2>&1'\n", i, i, i)
	}

	// Generate logger windows with race condition detection and redirection to log files
	for i := 1; i <= numFSMLoggerEEAs; i++ {
		fmt.Fprintf(file, "tmux new-window -n \"network_logger_%d\" bash -c 'go run -race ctng.go Logger L%d > logger_%d.log 2>&1'\n", i, i, i)
	}

	fmt.Fprintln(file, "\n# Attach to the tmux session")
	fmt.Fprintln(file, "tmux attach-session -t $SESSION")

	// Make the script executable
	err = os.Chmod("run.sh", 0755)
	if err != nil {
		return err
	}

	return nil
}
