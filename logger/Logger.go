package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	def "github.com/jik18001/CTngV3/def"
	rs "github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

type Logger struct {
	CTngID      def.CTngID                            `json:"CTngID"`
	Crypto      *def.GlobalCrypto                     `json:"Crypto,omitempty"`
	Settings    *def.Settings                         `json:"Settings,omitempty"`
	Client      *http.Client                          `json:"Client,omitempty"`
	Updates     map[def.CTngID]*def.Update_Logger     `json:"Updates,omitempty"`
	Updates_EEA map[def.CTngID]*def.Update_Logger_EEA `json:"Updates_EEA,omitempty"`
	PeriodNum   int                                   `json:"PeriodNum"`
	NumMonitors int                                   `json:"NumMonitors"`
	Mal         int                                   `json:"Mal"`
}

func NewLogger(CTngID def.CTngID, cryptofile string, settingfile string) *Logger {
	// Initialize a new StoredCrypto object.
	restoredcrypto := new(def.StoredCrypto)

	// Load the configuration from the file.
	def.LoadData(&restoredcrypto, cryptofile)
	crypto, err := def.DecodeCrypto(restoredcrypto)
	if err != nil {
		def.HandleError(err, "DecodeCrypto")
	}

	// Initalize a new Setting object
	restoredsetting := new(def.Settings)
	def.LoadData(&restoredsetting, settingfile)
	numMonitors := crypto.Total
	numMal := crypto.Threshold - 1
	Updates := make(map[def.CTngID]*def.Update_Logger, numMonitors)
	Updates_EEA := make(map[def.CTngID]*def.Update_Logger_EEA, numMonitors)
	for i := 0; i < numMonitors; i++ {
		id := def.CTngID(fmt.Sprintf("M%d", i+1))
		Updates_EEA[id] = &def.Update_Logger_EEA{
			MonitorID: id,
		}
	}
	loggerContext := Logger{
		CTngID:      CTngID,
		Crypto:      crypto,
		Settings:    restoredsetting,
		Updates:     Updates,
		Updates_EEA: Updates_EEA,
		PeriodNum:   1,
		NumMonitors: numMonitors,
		Mal:         numMal,
	}
	tr := &http.Transport{
		MaxIdleConnsPerHost: 300,
		MaxConnsPerHost:     300,
		WriteBufferSize:     1024 * 1024, // 1MB
		ReadBufferSize:      1024 * 1024, // 1MB
	}
	loggerContext.Client = &http.Client{
		Transport: tr,
	}
	return &loggerContext
}
func (l *Logger) Sign(msg []byte) (def.RSASig, error) {
	sig, err := l.Crypto.Sign(msg, l.CTngID)
	return sig, err
}

func (l *Logger) Verify(msg []byte, sig def.RSASig) error {
	err := l.Crypto.Verify(msg, sig)
	return err
}

// Function to calculate the greatest common divisor (GCD)
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Function to adjust the file size based on the GCD requirement
func adjustFileSize(numMonitorsm1, certificateSize, filesize int) int {
	remainder := filesize % numMonitorsm1
	if remainder == 0 {
		return filesize
	}
	return filesize + (numMonitorsm1 - remainder)
}

// limitations of RS encoding, each block needs to have the same size
// for simulation purposes, we assume certificate size of 5KB
// This means that file size needs to be divisible by the greatest common divsior of the product

func (l *Logger) GenerateSTH(rootHash []byte, size int) *def.STH {
	// Get the current timestamp in UTC RFC3339 format
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Create the STH
	sth := &def.STH{
		PeriodNum: l.PeriodNum,
		Size:      size,
		Timestamp: timestamp,
		Head:      rootHash,
		LID:       l.CTngID.String(),
		Signature: def.RSASig{}, // Placeholder for the signature
	}

	// Serialize the STH for signing
	sthBytes, err := json.Marshal(sth)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}

	signature, _ := l.Sign(sthBytes)
	sth.Signature = signature
	return sth
}

func (l *Logger) GenerateUpdate() {
	filesize := adjustFileSize(l.NumMonitors-l.Mal, l.Settings.Certificate_size, l.Settings.Certificate_size*l.Settings.Certificate_per_logger)
	numcerts := l.Settings.Certificate_per_logger
	// Initialize Reed-Solomon encoder
	enc, err := rs.New(l.NumMonitors-l.Mal, l.Mal)
	if err != nil {
		log.Fatalf("Error initializing Reed-Solomon encoder: %v", err)
	}
	// Create a slice to hold the data for each monitor
	data := make([][]byte, l.NumMonitors)
	for i := range data {
		data[i] = make([]byte, filesize/(l.NumMonitors-l.Mal))
	}
	// file the data portion
	for i, in := range data[:(l.NumMonitors - l.Mal)] {
		for j := range in {
			in[j] = byte((i + j) & 0xff)
		}
	}
	// Split the data into 5KB blocks and compute the Merkle Tree
	var dataBlocks []merkletree.DataBlock
	for i := range data[:(l.NumMonitors - l.Mal)] {
		for j := 0; j < len(data[i]); j += l.Settings.Certificate_size {
			end := j + l.Settings.Certificate_size
			if end > len(data[i]) {
				end = len(data[i])
			}
			dataBlocks = append(dataBlocks, &def.LeafBlock{Content: data[i][j:end]})
		}
	}
	// Generate Merkle Tree
	tree, err := def.GenerateMerkleTree(dataBlocks)
	def.HandleError(err, "MT Generation")
	rootHash := def.GenerateRootHash(tree)
	sth := l.GenerateSTH(rootHash, numcerts)

	// Encode the data if the mode is Reedsolomn
	if l.Settings.Distribution_Mode == def.EEA {
		err := enc.Encode(data)
		def.HandleError(err, "RS Encoding error")
		// Create a slice to hold the encoded data for each monitor
		var RSdataBlocks []merkletree.DataBlock
		for i := range data {
			RSdataBlocks = append(RSdataBlocks, &def.LeafBlock{Content: data[i]})
		}

		// Generate the second Merkle Tree
		RStree, err := def.GenerateMerkleTree(RSdataBlocks)
		def.HandleError(err, "Second Merkle Tree Generation")
		rootHashRS := def.GenerateRootHash(RStree)
		var rootblocks []merkletree.DataBlock
		rootblocks = append(rootblocks, &def.LeafBlock{Content: rootHashRS})
		rootblocks = append(rootblocks, &def.LeafBlock{Content: rootHash})
		newtree, err := def.GenerateMerkleTree(rootblocks)
		combinedroot := def.GenerateRootHash(newtree)
		newSTH := l.GenerateSTH(combinedroot, numcerts)
		//sthRS := l.GenerateSTH(rootHashRS, numcerts)
		for id, update := range l.Updates_EEA {
			index := def.GetIndex(id)
			//fmt.Println(index, idString)
			update.STH = *newSTH
			update.FileShare = data[index]
			poi, _ := def.GeneratePOI(RSdataBlocks, index)
			update.Head_rs = rootHashRS
			update.Head_cert = rootHash
			//update.STH_rs = *sthRS
			update.PoI = poi
		}
		return
	}
	for _, update := range l.Updates {
		update.STH = *sth
		update.File = update.File
	}

}

func (l *Logger) Send_Update_EEA() {
	monitors := def.GetMonitorURL(*l.Settings)
	for id, monitor := range monitors {
		url := "http://" + monitor + "/monitor/logger_update_EEA"
		update := l.Updates_EEA[id]
		update_json, err := json.Marshal(update)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		_, err = l.Client.Post(url, "application/json", bytes.NewBuffer(update_json))
		if err != nil {
			fmt.Println("Failed to send update to: ", update.MonitorID)
			//fmt.Println(update.FileShare)
		} else {
			fmt.Println("Update sent to ", update.MonitorID)
			//fmt.Println(update.FileShare)
		}

	}
	/*
		monitorip := l.Settings.Ipmap[monitor]
		monitorport := l.Settings.Portmap[monitor]
		fmt.Println(monitorip, ":", monitorport)
		url := "http://" + monitorip + ":" + monitorport + "/monitor/logger_update_EEA"
		resp, err := l.Client.Post(url, "application/json", bytes.NewBuffer(sth_json))
		if err != nil {
			fmt.Println("Failed to send update: ", err)
		} else {
			fmt.Println("Update sent successfully, response status:", resp.Status)
			defer resp.Body.Close()
		}*/
}

func StartLogger(id def.CTngID, cryptofile string, settingfile string) {
	newlogger := NewLogger(id, cryptofile, settingfile)
	newlogger.GenerateUpdate()
	fmt.Println(newlogger.Updates_EEA[def.CTngID("M1")].Head_cert)
	fmt.Println(newlogger.Updates_EEA[def.CTngID("M1")].Head_rs)
	newlogger.Send_Update_EEA()
}