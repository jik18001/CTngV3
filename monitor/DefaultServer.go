package monitor

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	def "github.com/jik18001/CTngV3/def"
)

func handleRequests(m *MonitorEEA) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	//endpoints
	//---------------------------------Shared------------------------------------------------------------------------
	gorillaRouter.HandleFunc("/monitor/PoM", bindContext(m, PoM_handler)).Methods("POST")
	//---------------------------------Transparency Updates----------------------------------------------------------
	gorillaRouter.HandleFunc("/monitor/logger_update", bindContext(m, logger_update_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/default_transparency_notification", bindContext(m, default_transparency_notification_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/default_transparency_request", bindContext(m, default_transparency_request_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/default_transparency_partial_signature", bindContext(m, default_transparency_partial_signature_handler)).Methods("POST")
	//---------------------------------Revocation Updates----------------------------------------------------------
	// gorillaRouter.HandleFunc("/monitor/ca_update_EEA", bindContext(m, ca_update_EEA_handler)).Methods("POST")
	// gorillaRouter.HandleFunc("/monitor/SRH", bindContext(m, ca_srh_handler)).Methods("POST")
	// gorillaRouter.HandleFunc("/monitor/revocation_notification", bindContext(m, revocation_notification_handler)).Methods("POST")
	// gorillaRouter.HandleFunc("/monitor/revocation_request", bindContext(m, revocation_request_handler)).Methods("POST")
	// gorillaRouter.HandleFunc("/monitor/revocation_partial_signature", bindContext(m, revocation_partial_signature_handler)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(def.BLUE+"(default) Listening on port:", m.Settings.Portmap[m.CTngID], def.RESET)
	err := http.ListenAndServe(":"+m.Settings.Portmap[m.CTngID], nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func StartMonitorServer(m *MonitorEEA) {
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
	handleRequests(m)
}
