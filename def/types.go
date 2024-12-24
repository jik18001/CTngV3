package def

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"
	merkletree "github.com/txaty/go-merkletree"
)

const PROTOCOL = "http://"

// PCB distribution mode
const DEFAULT = "default"
const EEA = "erasure encoding algorithm"

// monitor broadcasting modes
const MIN_WT = "minimal wait time"
const MIN_BC = "minimal bandwidth consumption"

// notification types
const TUEEA = "transparency update erasure encoding algorithm"
const RUEEA = "revocation update erasure encoding algorithm"
const TU = "transparency update"
const RU = "revocation update"

// State defintions
const INIT = "init"
const PRECOMMIT = "precommit"
const POSTCOMMIT = "postcommit"
const DONE = "done"
const POM = "PoM"

// Wakeup Labels
const WAKE_TU = "wake up tu"
const WAKE_TC = "wake up tc"
const WAKE_TM = "wake up tm"
const WAKE_TV = "wake up tv"
const WAKE_TR = "wake up tr"

type Context struct {
	Label   string
	Content interface{}
}

type Settings struct {
	Ipmap                  map[CTngID]string `json:"Ipmap"`
	Portmap                map[CTngID]string `json:"Portmap"`
	Num_Monitors           int               `json:"Num_Monitors"`
	Mal                    int               `json:"Mal"`
	Update_Wait_time       int               `json:"Update_Wait_time"`
	Mature_Wait_time       int               `json:"Mature_Wait_time"`
	Response_Wait_time     int               `json:"Response_Wait_time "`
	Verification_Wait_time int               `json:"Verification_Wait_time"`
	MUD                    int               `json:"MUD"`
	Distribution_Mode      string            `json:"Distribution_Mode"`
	Broadcasting_Mode      string            `json:"Broadcasting_Mode"`
	Num_CAs                int               `json:"Num_CAs"`
	CRV_size               int               `json:"CRV_size"`
	Revocation_ratio       float64           `json:"Revocation_ratio"`
	Num_Loggers            int               `json:"Num_Loggers"`
	Certificate_size       int               `json:"Certificate_size"`
	Certificate_per_logger int               `json:"Certificate_per_logger"`
}

// Logger related
type STH struct {
	LID       string `json:"lid"`
	PeriodNum int    `json:"period"`
	Size      int    `json:"size"`
	Timestamp string `json:"timestamp"` //Timestamp is a UTC RFC3339 string
	Head      []byte `json:"head"`
	Signature RSASig `json:"signature"`
}

type PoI struct {
	Proof *merkletree.Proof `json:"proof,omitempty"`
}

type SRH struct {
	CAID      string `json:"CAID"`
	PeriodNum int    `json:"period"`
	Head      []byte `json:"head,omitempty"`
	Timestamp string `json:"timestamp"`
	Signature RSASig `json:"signature"`
}

type DCRV struct {
	BitVector *bitset.BitSet
}

type Update_Logger struct {
	STH STH `json:"STH,omitempty"`
	//MonitorID CTngID `json:"MonitorID"`
	File [][]byte `json:"File,omitempty"`
}

// Logger Update: Erasure Encoding version
type Update_Logger_EEA struct {
	MonitorID CTngID `json:"MonitorID"`
	FileShare []byte `json:"FileShare,omitempty"` //certs_Mi
	Head_cert []byte `json:"Head_cert,omitempty"` //head_cert
	Head_rs   []byte `json:"Head_rs,omitempty"`   //Headrs
	PoI       PoI    `json:"PoI,omitempty"`
	STH       STH    `json:"STH,omitempty"` //LID and Period number are in the STH
}

type Update_CA struct {
	SRH  SRH      `json:"SRH,omitempty"`
	File [][]byte `json:"File,omitempty"`
}

// CA Update: Erasure Encoding version
type Update_CA_EEA struct {
	MonitorID   CTngID `json:"MonitorID"`
	FileShare   []byte `json:"FileShare,omitempty"`
	Head_rs     []byte `json:"Head_rs,omitempty"`
	PoI         PoI    `json:"PoI,omitempty"`
	SRH         SRH    `json:"SRH,omitempty"` //CAID and Period number are in the SRH
	OriginalLen int    `json:"OriginalLen,omitempty"`
}

// Monitor related definitions
type Notification struct {
	Type       string `json:"type"`
	Originator CTngID `json:"originator"`
	Monitor    CTngID `json:"monitor,omitempty"`
	Sender     string `json:"sender"` // identifies the sender URL for query
}

// could be a conflicting STH or SRH
type CPoM struct {
	Entity_Convicted CTngID
	MetaData1        interface{}
	MetaData2        interface{}
}

type APoM struct {
	Entity_Convicted CTngID
	Signature        string //serialzied threshold signature
}

func Generate_IP_Json_template(num_ca int, num_logger int, num_monitor int, mal int, ca_mask string, ca_offset int, logger_mask string, logger_offset int, monitor_mask string, monitor_offset int, starting_port int, update_wait_time int, mature_wait_time int, response_wait_time int, verification_wait_time int, mud int, dmode string, bmode string, crvsize int, revocation_ratio float64, certificate_size int, certificate_per_logger int) *Settings {
	ipmap := make(map[CTngID]string)
	portmap := make(map[CTngID]string)

	current_port := starting_port
	/*
		for i := 0; i < num_ca; i++ {
			id := CTngID(fmt.Sprintf("C%d", i+1))
			ipmap[id] = ca_mask + strconv.Itoa((i%10 + ca_offset))
			portmap[id] = strconv.Itoa(current_port)
			current_port++
		}
	*/

	for i := 0; i < num_ca; i++ {
		id := CTngID(fmt.Sprintf("C%d", i+1))
		ipmap[id] = ca_mask + strconv.Itoa((i + ca_offset))
		portmap[id] = strconv.Itoa(current_port)
		current_port++
	}

	for i := 0; i < num_logger; i++ {
		id := CTngID(fmt.Sprintf("L%d", i+1))
		ipmap[id] = logger_mask + strconv.Itoa(i+logger_offset)
		portmap[id] = strconv.Itoa(current_port)
		current_port++
	}

	for i := 0; i < num_monitor; i++ {
		id := CTngID(fmt.Sprintf("M%d", i+1))
		ipmap[id] = monitor_mask + strconv.Itoa(i+monitor_offset)
		portmap[id] = strconv.Itoa(current_port)
		current_port++
	}

	settings := Settings{
		Ipmap:                  ipmap,
		Portmap:                portmap,
		Num_Monitors:           num_monitor,
		Mal:                    mal,
		Update_Wait_time:       update_wait_time,
		Mature_Wait_time:       mature_wait_time,
		Response_Wait_time:     response_wait_time,
		Verification_Wait_time: verification_wait_time,
		MUD:                    mud,
		Distribution_Mode:      dmode,
		Broadcasting_Mode:      bmode,
		Num_CAs:                num_ca,
		CRV_size:               crvsize,
		Revocation_ratio:       revocation_ratio,
		Num_Loggers:            num_logger,
		Certificate_size:       certificate_size,
		Certificate_per_logger: certificate_per_logger,
	}

	return &settings
}

func GetMonitorURL(settings Settings) map[CTngID]string {
	monitors := make(map[CTngID]string)
	for key, ip := range settings.Ipmap {
		keystring := key.String()
		if keystring[0] == 'M' {
			if port, exists := settings.Portmap[key]; exists {
				monitors[key] = ip + ":" + port
			}
		}
	}
	return monitors
}

func GetIDs(prefix byte, settings Settings) []CTngID {
	ids := make([]CTngID, 0)
	for key, _ := range settings.Ipmap {
		keystring := key.String()
		if keystring[0] == prefix {
			if _, exists := settings.Portmap[key]; exists {
				ids = append(ids, key)
			}
		}
	}
	return ids
}

func MapIDtoInt(id CTngID) (int, error) {
	// Extract the prefix (first character)
	prefix := string(id[0])

	// Remove the prefix from the ID
	trimmedID := strings.TrimPrefix(string(id), prefix)

	// Convert the remaining part to an integer
	num, err := strconv.Atoi(trimmedID)
	if err != nil {
		return 0, fmt.Errorf("invalid ID format: %s", id)
	}

	// Subtract 1 to start the mapping from 0
	return num - 1, nil
}
