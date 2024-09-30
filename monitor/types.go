package monitor

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	def "github.com/jik18001/CTngV3/def"
)

type MonitorEEA struct {
	CTngID            def.CTngID
	Self_ip_port      string
	Crypto            *def.GlobalCrypto
	Settings          *def.Settings
	Broadcast_targets map[def.CTngID]string
	FSMCAEEAs         []*FSMCAEEA
	FSMLoggerEEAs     []*FSMLoggerEEA
	Client            *http.Client
	Hashlock          sync.RWMutex // Concurrency control
}

type MonitorSignedData struct {
	Type      string
	CTngID    def.CTngID
	Signature string
}

type countWriter struct {
	count *int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n := len(p)
	*cw.count += int64(n)
	return n, nil
}

// Function to initialize a MonitorEEA with specified numbers of FSMCAEEA and FSMLoggerEEA instances
func NewMonitorEEA(CTngID def.CTngID, cryptofile string, settingfile string) *MonitorEEA {
	// Initialize a new StoredCrypto object.
	restoredconfig := new(def.StoredCrypto)
	// Initialize a new Setting object.
	restoredsetting := new(def.Settings)
	// Load the configuration from the file.
	def.LoadData(&restoredsetting, settingfile)
	def.LoadData(&restoredconfig, cryptofile)
	config, err := def.DecodeCrypto(restoredconfig)
	if err != nil {
		def.HandleError(err, "DecodeCrypto")
	}
	numFSMCAEEAs := restoredsetting.Num_CAs
	numFSMLoggerEEAs := restoredsetting.Num_Loggers
	numMonitors := restoredsetting.Num_Monitors
	fsmCAs := make([]*FSMCAEEA, numFSMCAEEAs)
	fsmLoggers := make([]*FSMLoggerEEA, numFSMLoggerEEAs)
	// CA to be added here

	for i := 0; i < numFSMCAEEAs; i++ {
		id := def.CTngID(fmt.Sprintf("C%d", i+1))
		fsmCAs[i] = &FSMCAEEA{
			CTngID:        id,
			State:         def.INIT,
			lock:          sync.RWMutex{},
			Period:        0,
			SRH:           def.SRH{},
			Updates:       make(map[def.CTngID]def.Update_CA_EEA),
			Notifications: []def.Notification{},
			DataFragments: make([][]byte, numMonitors),
			DataCheck:     false,
			Signaturelist: []def.SigFragment{},
			Signature:     def.ThresholdSig{},
			APoM:          def.APoM{},
			CPoM:          def.CPoM{},
			StartTime:     time.Now(),
			TrafficCount:  0,
			UpdateCount:   0,
		}
	}

	for i := 0; i < numFSMLoggerEEAs; i++ {
		id := def.CTngID(fmt.Sprintf("L%d", i+1))
		fsmLoggers[i] = &FSMLoggerEEA{
			CTngID:        id,
			State:         def.INIT,
			lock:          sync.RWMutex{},
			Period:        0,
			STH:           def.STH{},
			Updates:       make(map[def.CTngID]def.Update_Logger_EEA),
			Notifications: []def.Notification{},
			DataFragments: make([][]byte, numMonitors),
			DataCheck:     false,
			Signaturelist: []def.SigFragment{},
			Signature:     def.ThresholdSig{},
			APoM:          def.APoM{},
			CPoM:          def.CPoM{},
			StartTime:     time.Now(),
			TrafficCount:  0,
			UpdateCount:   0,
		}
	}

	allmonitors := def.GetMonitorURL(*restoredsetting)
	targets := make(map[def.CTngID]string)
	var ip_port string
	for key, value := range allmonitors {
		if key.String() != CTngID.String() {
			targets[key] = value
		} else {
			ip_port = value
		}
	}
	return &MonitorEEA{
		CTngID:            CTngID,
		Self_ip_port:      ip_port,
		Crypto:            config,
		Broadcast_targets: targets,
		Settings:          restoredsetting,
		FSMCAEEAs:         fsmCAs,
		FSMLoggerEEAs:     fsmLoggers,
		Hashlock:          sync.RWMutex{},
	}
}

func (m *MonitorEEA) ThresholdSign(msg string) def.SigFragment {
	sigfrag1, _ := m.Crypto.ThresholdSign(msg, m.CTngID)
	return sigfrag1
}

func (m *MonitorEEA) FragmentVerify(msg string, sigfrag def.SigFragment) error {
	err := m.Crypto.FragmentVerify(msg, sigfrag)
	return err
}

func (m *MonitorEEA) Aggregate(sigfrags []def.SigFragment) def.ThresholdSig {
	sig, _ := m.Crypto.ThresholdAggregate(sigfrags)
	return sig
}

func (m *MonitorEEA) ThresholdVerify(msg string, sig def.ThresholdSig) error {
	err := m.Crypto.ThresholdVerify(msg, sig)
	return err
}

func StartMonitorEEA(id def.CTngID, cryptofile string, settingfile string) {
	newmonitor := NewMonitorEEA(id, cryptofile, settingfile)
	//fmt.Println(newmonitor.CTngID)
	StartMonitorEEAServer(newmonitor)
}
