package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	def "github.com/jik18001/CTngV3/def"
)

func bindContext(context *MonitorEEA, fn func(context *MonitorEEA, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleRequests_EEA(m *MonitorEEA) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	//endpoints
	//---------------------------------Shared------------------------------------------------------------------------
	gorillaRouter.HandleFunc("/monitor/PoM", bindContext(m, PoM_handler)).Methods("POST")
	//---------------------------------Transparency Updates----------------------------------------------------------
	gorillaRouter.HandleFunc("/monitor/logger_update_EEA", bindContext(m, logger_update_EEA_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/STH", bindContext(m, logger_sth_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/transparency_notification", bindContext(m, transparency_notification_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/transparency_request", bindContext(m, transparency_request_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/transparency_partial_signature", bindContext(m, transparency_partial_signature_handler)).Methods("POST")
	//---------------------------------Revocation Updates----------------------------------------------------------
	gorillaRouter.HandleFunc("/monitor/ca_update_EEA", bindContext(m, ca_update_EEA_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/SRH", bindContext(m, ca_srh_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/revocation_notification", bindContext(m, revocation_notification_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/revocation_request", bindContext(m, revocation_request_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/revocation_partial_signature", bindContext(m, revocation_partial_signature_handler)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(def.BLUE+"Listening on port:", m.Settings.Portmap[m.CTngID], def.RESET)
	err := http.ListenAndServe(":"+m.Settings.Portmap[m.CTngID], nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func broadcastEEA(m *MonitorEEA, endpoint string, data []byte) {
	monitors := def.GetMonitorURL(*m.Settings)
	for _, monitor := range monitors {
		url := "http://" + monitor + endpoint
		_, err := m.Client.Post(url, "application/json", bytes.NewBuffer(data))
		if err != nil {
			//fmt.Println("Failed to send update: ", err)
		}
	}
}

func PoM_handler(m *MonitorEEA, w http.ResponseWriter, r *http.Request) {

}

/*
func PeriodicTasks(m *MonitorEEA) {
	// Immediately queue up the next task to run at next MUD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	fmt.Println("Entering Periodic Task")
	filename := m.CTngID.String() + ".json"
	m.DumpConvergeTimesToFile(filename)
	f := func() {
		PeriodicTasks(m)
	}
	time.AfterFunc(time.Duration(m.Settings.MUD)*time.Second, f)
}
*/

func StartMonitorEEAServer(m *MonitorEEA) {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 300,
		MaxConnsPerHost:     300,
		WriteBufferSize:     1024 * 1024, // 1MB
		ReadBufferSize:      1024 * 1024, // 1MB
	}
	m.Client = &http.Client{
		Transport: tr,
	}
	// HTTP Server Loop
	//go PeriodicTasks(m)
	filename := m.CTngID.String() + ".json"
	m.DumpConvergeTimesToFile(filename)
	f := func() {
		m.DumpConvergeTimesToFile(filename)
	}
	time.AfterFunc(time.Duration(m.Settings.MUD)*time.Second, f)
	fmt.Println("Current Time:", time.Now().Format(time.RFC3339))
	handleRequests_EEA(m)
}

// ConvergeTimeRecord holds the ID and converge time of each FSMLoggerEEA and FSMCAEEA
type ConvergeTimeRecord struct {
	MonitorID    string  `json:"monitor_id"`
	EntityID     string  `json:"entity_id"`   // Can represent LoggerID or CAID
	EntityType   string  `json:"entity_type"` // "Logger" or "CA"
	ConvergeTime float64 `json:"converge_time"`
	Traffic      string  `json:"traffic"`
	UpdateCount  int     `json:"update_count"`
}

func (m *MonitorEEA) DumpConvergeTimesToFile(filename string) error {
	var convergeTimes []ConvergeTimeRecord

	// Iterate over all FSMLoggers
	for _, fsmLogger := range m.FSMLoggerEEAs {
		fsmLogger.lock.RLock()
		convergeTimes = append(convergeTimes, ConvergeTimeRecord{
			EntityID:     fsmLogger.CTngID.String(),
			MonitorID:    m.CTngID.String(),
			EntityType:   "Logger",
			ConvergeTime: fsmLogger.ConvergeTime.Seconds(),
			Traffic:      formatTraffic(fsmLogger.TrafficCount),
			UpdateCount:  fsmLogger.UpdateCount,
		})
		fsmLogger.lock.RUnlock()
	}

	// Iterate over all FSMCAs
	for _, fsmCA := range m.FSMCAEEAs {
		fsmCA.lock.RLock()
		convergeTimes = append(convergeTimes, ConvergeTimeRecord{
			EntityID:     fsmCA.CTngID.String(),
			MonitorID:    m.CTngID.String(),
			EntityType:   "CA",
			ConvergeTime: fsmCA.ConvergeTime.Seconds(),
			Traffic:      formatTraffic(fsmCA.TrafficCount),
			UpdateCount:  fsmCA.UpdateCount,
		})
		fsmCA.lock.RUnlock()
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(convergeTimes, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal converge times: %v", err)
	}

	// Write to file
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write converge times to file: %v", err)
	}

	fmt.Printf("Converge times successfully dumped to %s\n", filename)
	return nil
}

// formatTraffic converts traffic in bytes to a human-readable format (KB, MB, GB, etc.)
func formatTraffic(bytes int) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
