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
	// Initialize a new Settings object.
	restoredsetting := new(def.Settings)
	// Load the configuration from the files.
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

	// Initialize FSMCAEEA instances
	for i := 0; i < numFSMCAEEAs; i++ {
		id := def.CTngID(fmt.Sprintf("C%d", i+1))
		fsmCAs[i] = &FSMCAEEA{
			CTngID:               id,
			State:                def.INIT,
			lock:                 sync.RWMutex{},
			Period:               0,
			SRH:                  def.SRH{},
			Updates:              make(map[def.CTngID]def.Update_CA_EEA),
			Notifications:        make([]def.Notification, 0),
			DataFragments:        make([][]byte, numMonitors),
			DataFragment_Counter: 0,
			DataCheck:            false,
			Signaturelist:        make([]def.SigFragment, 0),
			Signature:            def.ThresholdSig{},
			APoM:                 def.APoM{},
			CPoM:                 def.CPoM{},
			TrafficCount:         0,
			UpdateCount:          0,
			StartTime:            time.Now(),
			ConvergeTime:         0,
			Bmodes:               make([]string, numMonitors),
			EEA_Notifications:    make([][]def.Notification, numMonitors),
		}
	}

	// Initialize FSMLoggerEEA instances
	for i := 0; i < numFSMLoggerEEAs; i++ {
		id := def.CTngID(fmt.Sprintf("L%d", i+1))
		fsmLoggers[i] = &FSMLoggerEEA{
			CTngID:               id,
			State:                def.INIT,
			lock:                 sync.RWMutex{},
			Period:               0,
			STH:                  def.STH{},
			Updates:              make(map[def.CTngID]def.Update_Logger_EEA),
			DataFragments:        make([][]byte, numMonitors),
			Bmode:                restoredsetting.Broadcasting_Mode,
			Bmodes:               make([]string, numMonitors),
			EEA_Notifications:    make([][]def.Notification, numMonitors),
			DataFragment_Counter: 0,
			Data:                 make([][]byte, 0),
			DataCheck:            false,
			Signaturelist:        make([]def.SigFragment, 0),
			Signature:            def.ThresholdSig{},
			APoM:                 def.APoM{},
			CPoM:                 def.CPoM{},
			StartTime:            time.Now(),
			TrafficCount:         0,
			UpdateCount:          0,
			ConvergeTime:         0,
		}

		// Initialize Bmodes per fragment to the global Bmode
		for j := 0; j < numMonitors; j++ {
			fsmLoggers[i].Bmodes[j] = restoredsetting.Broadcasting_Mode
		}
		for j := 0; j < numMonitors; j++ {
			fsmCAs[i].Bmodes[j] = restoredsetting.Broadcasting_Mode
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

func StartMonitor(id def.CTngID, cryptofile string, settingfile string) {
	newmonitor := NewMonitorEEA(id, cryptofile, settingfile)
	fmt.Println(newmonitor.Settings.Distribution_Mode)
	if newmonitor.Settings.Distribution_Mode == def.EEA {
		fmt.Println("Starting EEA Server")
		StartMonitorEEAServer(newmonitor)
	} else {
		fmt.Println("Starting Default Server")
		StartMonitorServer(newmonitor)
	}

}
