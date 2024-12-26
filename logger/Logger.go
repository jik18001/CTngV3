package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
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
	Update      *def.Update_Logger                    `json:"Update,omitempty"`
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
	var Update *def.Update_Logger
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
		Update:      Update,
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
	// Instead of: enc, err := rs.New(l.NumMonitors - l.Mal, l.Mal)
	// We'll define k=Mal+1, and m=NumMonitors-k
	k := l.Mal + 1         // Number of data shards
	m := l.NumMonitors - k // Number of parity shards
	enc, err := rs.New(k, m)
	if err != nil {
		log.Fatalf("Error initializing Reed-Solomon encoder: %v", err)
	}

	// We'll compute the total file size as before
	filesize := adjustFileSize(k, l.Settings.Certificate_size,
		l.Settings.Certificate_size*l.Settings.Certificate_per_logger)

	// Decide how many blocks total to allocate
	// We still want to produce 'n = NumMonitors' slices in EEA mode
	// because we eventually want each of the n monitors to get one block.
	numBlocks := l.NumMonitors
	if l.Settings.Distribution_Mode != def.EEA {
		// If NOT in EEA mode, we might only allocate k blocks
		numBlocks = k
	}

	// Allocate 'data' slices. Each block is filesize/k bytes.
	data := make([][]byte, numBlocks)
	for i := range data {
		// For data shards, we divide by k (not by NumMonitors - Mal).
		data[i] = make([]byte, filesize/k)
	}

	// Fill the first k blocks with some dummy data for the example:
	// (In practice, this is where you'd write your actual certificate bytes.)
	for i, in := range data[:k] {
		for j := range in {
			in[j] = byte((i + j) & 0xff)
		}
	}

	// Now build a Merkle tree of the actual data blocks (only the first k).
	var dataBlocks []merkletree.DataBlock
	for i := 0; i < k; i++ {
		// chunk them by l.Settings.Certificate_size
		for j := 0; j < len(data[i]); j += l.Settings.Certificate_size {
			end := j + l.Settings.Certificate_size
			if end > len(data[i]) {
				end = len(data[i])
			}
			dataBlocks = append(dataBlocks, &def.LeafBlock{Content: data[i][j:end]})
		}
	}

	// Generate the "certificate" Merkle Tree, rootHash, and STH as normal
	tree, err := def.GenerateMerkleTree(dataBlocks)
	def.HandleError(err, "MT Generation")
	rootHash := def.GenerateRootHash(tree)
	sth := l.GenerateSTH(rootHash, l.Settings.Certificate_per_logger)

	// If we're in erasure-encoding mode (EEA), do the encoding
	if l.Settings.Distribution_Mode == def.EEA {
		// Encode the data: data[:k] are data shards, data[k:] are parity
		err := enc.Encode(data)
		def.HandleError(err, "RS Encoding error")

		// Build a second Merkle tree of the entire data[] (k+m = NumMonitors blocks)
		var RSdataBlocks []merkletree.DataBlock
		for i := range data {
			RSdataBlocks = append(RSdataBlocks, &def.LeafBlock{Content: data[i]})
		}

		RStree, err := def.GenerateMerkleTree(RSdataBlocks)
		def.HandleError(err, "Second Merkle Tree Generation")
		rootHashRS := def.GenerateRootHash(RStree)

		// Combine the two root hashes into yet another small Merkle tree
		var rootblocks []merkletree.DataBlock
		rootblocks = append(rootblocks, &def.LeafBlock{Content: rootHashRS})
		rootblocks = append(rootblocks, &def.LeafBlock{Content: rootHash})
		newtree, err := def.GenerateMerkleTree(rootblocks)
		def.HandleError(err, "Third Merkle Tree Generation")
		combinedroot := def.GenerateRootHash(newtree)
		newSTH := l.GenerateSTH(combinedroot, l.Settings.Certificate_per_logger)

		// Assign each monitor’s share and PoI
		for id, update := range l.Updates_EEA {
			index := def.GetIndex(id) // e.g. M1 => index=0, M2 => 1, etc.
			update.STH = *newSTH
			update.FileShare = data[index] // The shard for that monitor
			poi, _ := def.GeneratePOI(newtree, RSdataBlocks, index)
			update.Head_rs = rootHashRS
			update.Head_cert = rootHash
			update.PoI = poi
		}
		return
	}

	// Else (not EEA), just store the raw data in l.Update
	l.Update = &def.Update_Logger{
		STH:  *sth,
		File: data,
	}
}

func (l *Logger) sendUpdateToMonitor(urlSuffix string, update interface{}, monitorID string) int {
	url := "http://" + monitorID + urlSuffix
	updateJSON, err := json.Marshal(update)
	if err != nil {
		log.Fatalf("Failed to marshal update: %v", err)
	}

	trafficSize := len(updateJSON) // Measure the size of the JSON data
	_, err = l.Client.Post(url, "application/json", bytes.NewBuffer(updateJSON))
	if err != nil {
		fmt.Printf("Failed to send update to: %s\nError: %v\n", monitorID, err)
	} else {
		fmt.Printf("Update sent to %s, Traffic: %d bytes\n", monitorID, trafficSize)
	}

	return trafficSize
}

func (l *Logger) Send_Update_EEA() {
	monitors := def.GetMonitorURL(*l.Settings)

	// We'll keep track of total traffic with an atomic counter
	var totalTraffic int64

	// We use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	for id, monitorURL := range monitors {
		update := l.Updates_EEA[id]

		// For each monitor, spawn a goroutine
		wg.Add(1)
		go func(url string, upd *def.Update_Logger_EEA) {
			defer wg.Done()

			// Introduce random delay of 10–50 ms
			delay := time.Duration(rand.Intn(41)+10) * time.Millisecond
			time.Sleep(delay)

			// Now actually send the update
			traffic := l.sendUpdateToMonitor("/monitor/logger_update_EEA", upd, url)

			// Accumulate into the totalTraffic
			atomic.AddInt64(&totalTraffic, int64(traffic))

		}(monitorURL, update)
	}

	// Wait until all goroutines have finished
	wg.Wait()

	// Convert from int64 to int for printing, if desired
	finalTraffic := atomic.LoadInt64(&totalTraffic)
	fmt.Printf("Total traffic sent for EEA updates: %d bytes\n", finalTraffic)
}

/*
	func (l *Logger) Send_Update_EEA() {
		monitors := def.GetMonitorURL(*l.Settings)
		totalTraffic := 0

		for id, monitor := range monitors {
			update := l.Updates_EEA[id]
			totalTraffic += l.sendUpdateToMonitor("/monitor/logger_update_EEA", update, monitor)
		}

		fmt.Printf("Total traffic sent for EEA updates: %d bytes\n", totalTraffic)
	}
*/
func (l *Logger) Send_Update() {
	monitors := def.GetMonitorURL(*l.Settings)
	totalTraffic := 0

	for _, monitor := range monitors {
		totalTraffic += l.sendUpdateToMonitor("/monitor/logger_update", l.Update, monitor)
	}

	fmt.Printf("Total traffic sent for general updates: %d bytes\n", totalTraffic)
}

func StartLogger(id def.CTngID, cryptofile string, settingfile string) {
	// Add a random delay between 0 and 4 seconds
	rand.Seed(time.Now().UnixNano())                   // Seed the random number generator
	delay := time.Duration(rand.Intn(5)) * time.Second // Random delay in the range [0, 4] seconds
	time.Sleep(delay)                                  // Introduce the delay
	newlogger := NewLogger(id, cryptofile, settingfile)
	newlogger.GenerateUpdate()
	if newlogger.Settings.Distribution_Mode == def.EEA {
		fmt.Println(newlogger.Updates_EEA[def.CTngID("M1")].Head_cert)
		fmt.Println(newlogger.Updates_EEA[def.CTngID("M1")].Head_rs)
		newlogger.Send_Update_EEA()
	} else {
		fmt.Println(newlogger.Update.STH)
		newlogger.Send_Update()
	}
}
