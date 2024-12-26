package ca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	bitset "github.com/bits-and-blooms/bitset"
	def "github.com/jik18001/CTngV3/def"
	rs "github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

type CA struct {
	CTngID      def.CTngID                        `json:"CTngID"`
	Crypto      *def.GlobalCrypto                 `json:"Crypto,omitempty"`
	Settings    *def.Settings                     `json:"Settings,omitempty"`
	Client      *http.Client                      `json:"Client,omitempty"`
	Updates     map[def.CTngID]*def.Update_CA     `json:"Updates,omitempty"`
	Updates_EEA map[def.CTngID]*def.Update_CA_EEA `json:"Updates_EEA,omitempty"`
	PeriodNum   int                               `json:"PeriodNum"`
	NumMonitors int                               `json:"NumMonitors"`
	Mal         int                               `json:"Mal"`
}

func NewCA(CTngID def.CTngID, cryptofile string, settingfile string) *CA {
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
	Updates_EEA := make(map[def.CTngID]*def.Update_CA_EEA, numMonitors)
	Updates := make(map[def.CTngID]*def.Update_CA, numMonitors)
	for i := 0; i < numMonitors; i++ {
		id := def.CTngID(fmt.Sprintf("M%d", i+1))
		Updates_EEA[id] = &def.Update_CA_EEA{
			MonitorID: id,
		}
	}

	CAContext := CA{
		CTngID:      CTngID,
		Crypto:      crypto,
		Settings:    restoredsetting,
		Updates:     Updates,
		Updates_EEA: Updates_EEA,
		PeriodNum:   1,
		NumMonitors: numMonitors,
		Mal:         numMal,
	}
	tr := &http.Transport{}
	CAContext.Client = &http.Client{
		Transport: tr,
	}
	return &CAContext
}

func (ca *CA) Sign(msg []byte) (def.RSASig, error) {
	sig, err := ca.Crypto.Sign(msg, ca.CTngID)
	return sig, err
}

func (ca *CA) Verify(msg []byte, sig def.RSASig) error {
	err := ca.Crypto.Verify(msg, sig)
	return err
}

// Function to calculate the greatest common divisor (GCD)
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func GenerateRandomCompressedDCRV(totalBits int, density float64) []byte {
	numOnes := int(float64(totalBits) * density)
	positions := make(map[int]bool)
	var result []int

	for len(positions) < numOnes {
		position := rand.Intn(totalBits)
		if !positions[position] {
			positions[position] = true
			result = append(result, position)
		}
	}
	dcrv := bitset.New(uint(totalBits))
	for _, position := range result {
		dcrv.Set(uint(position))
	}
	dcrv_bytes, _ := dcrv.MarshalBinary()
	compressed, _ := def.CompressData(dcrv_bytes)
	return compressed
}

func (ca *CA) GenerateSRH(crvbytes []byte, dcrvbytes []byte) *def.SRH {
	// Get the current timestamp in UTC RFC3339 format
	timestamp := time.Now().UTC().Format(time.RFC3339)
	hcrv, _ := def.GenerateSHA256(crvbytes)
	hdcrv, _ := def.GenerateSHA256(dcrvbytes)
	// Create the SRH
	srh := &def.SRH{
		CAID:      ca.CTngID.String(),
		PeriodNum: ca.PeriodNum,
		Timestamp: timestamp,
		Signature: def.RSASig{}, // Placeholder for the signature
	}
	// Serialize the SRH for signing
	srhBytes, err := json.Marshal(srh)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}
	combine1 := append(srhBytes, hcrv...)
	combine2 := append(combine1, hdcrv...)
	signature, _ := ca.Sign(combine2)
	srh.Signature = signature
	//fmt.Println(hcrv)
	//fmt.Println(srh)
	return srh
}

func (ca *CA) GenerateSRHEEA(crvbytes []byte, dcrvbytes []byte, rootHash []byte) *def.SRH {
	// Get the current timestamp in UTC RFC3339 format
	timestamp := time.Now().UTC().Format(time.RFC3339)
	hcrv, _ := def.GenerateSHA256(crvbytes)
	hdcrv, _ := def.GenerateSHA256(dcrvbytes)
	combine1 := append(hcrv, hdcrv...)
	combine2 := append(combine1, rootHash...)
	// Create the SRH
	srh := &def.SRH{
		CAID:      ca.CTngID.String(),
		Head:      combine2,
		PeriodNum: ca.PeriodNum,
		Timestamp: timestamp,
		Signature: def.RSASig{}, // Placeholder for the signature
	}
	// Serialize the SRH for signing
	srhBytes, err := json.Marshal(srh)
	if err != nil {
		log.Fatalf("Failed to serialize STH: %v", err)
	}
	signature, _ := ca.Sign(srhBytes)
	srh.Signature = signature
	return srh
}

func (ca *CA) GenerateUpdateEEA() []byte {
	totalBits := ca.Settings.CRV_size
	density := ca.Settings.Revocation_ratio
	mode := ca.Settings.Distribution_Mode

	// Instead of "ca.NumMonitors - ca.Mal" for data, define:
	// k = Mal+1, m = NumMonitors - k
	k := ca.Mal + 1         // CHANGED: data shards
	m := ca.NumMonitors - k // CHANGED: parity shards
	fmt.Println("Number of monitors:", ca.NumMonitors)
	fmt.Println("Number of data shares (k):", k)
	fmt.Println("Number of parity shares (m):", m)

	// Initialize Reed-Solomon with (k, m)
	enc, err := rs.New(k, m) // CHANGED: use (k, m)
	if err != nil {
		log.Fatalf("Error initializing Reed-Solomon encoder: %v", err)
	}

	// Generate a random compressed DCRV
	dcrv := GenerateRandomCompressedDCRV(totalBits, density)

	// We'll split dcrv among the k data shards. Each shard has dataSize = len(dcrv)/k (plus padding if needed).
	dataSize := len(dcrv) / k // CHANGED
	if dataSize == 0 {
		dataSize = 1 // handle edge case if dcrv is very small
	}
	fmt.Println("length of DCRV post-compression:", len(dcrv))
	fmt.Println("datasize of RS-encoded post-compression DCRV:", dataSize)

	// Create 'NumMonitors' slices total, because we eventually produce k+m shards
	data := make([][]byte, ca.NumMonitors) // CHANGED
	// Fill the first k slices with actual data from dcrv
	for i := 0; i < k; i++ {
		start := i * dataSize
		end := start + dataSize
		if end > len(dcrv) {
			end = len(dcrv)
		}
		data[i] = dcrv[start:end]
	}

	// Pad each slice to dataSize if needed
	for i := range data {
		if len(data[i]) < dataSize {
			padded := make([]byte, dataSize)
			copy(padded, data[i])
			data[i] = padded
		}
	}

	// If EEA is used, do the RS encoding
	if mode == def.EEA {
		err := enc.Encode(data) // data[0..k-1] = data shards, data[k..k+m-1] = parity
		def.HandleError(err, "RS Encoding error")

		// Create a slice to hold the data blocks for Merkle generation
		var RSdataBlocks []merkletree.DataBlock
		for i := range data {
			RSdataBlocks = append(RSdataBlocks, &def.LeafBlock{Content: data[i]})
		}

		// Generate Merkle Tree of all k+m shards
		RStree, err := def.GenerateMerkleTree(RSdataBlocks)
		def.HandleError(err, "RS Merkle Tree Generation")
		rootHashRS := def.GenerateRootHash(RStree)

		// SRHEEA creation
		SRHEEA := ca.GenerateSRHEEA(dcrv, dcrv, rootHashRS)
		originalLen := len(dcrv)

		// Assign each shard to the corresponding monitor
		for id, update := range ca.Updates_EEA {
			index := def.GetIndex(id)
			update.SRH = *SRHEEA
			update.FileShare = data[index]
			poi, _ := def.GeneratePOI(RStree, RSdataBlocks, index)
			update.Head_rs = rootHashRS
			update.PoI = poi
			update.OriginalLen = originalLen
			ca.Updates_EEA[id] = update
		}
		return dcrv
	}

	// If not in EEA mode, we do not use Reed-Solomon
	SRH := ca.GenerateSRH(dcrv, dcrv)
	for _, update := range ca.Updates {
		update.SRH = *SRH
		// update.File = update.File // not changed
	}
	return dcrv
}

func broadcast(ca *CA, endpoint string, data []byte) {
	monitors := def.GetMonitorURL(*ca.Settings)
	for _, monitor := range monitors {
		url := "http://" + monitor + endpoint
		_, err := ca.Client.Post(url, "application/json", bytes.NewBuffer(data))
		if err != nil {
			fmt.Println("Failed to send update: ", err)
		}
	}
}

func (ca *CA) Send_Update_EEA() {
	monitors := def.GetMonitorURL(*ca.Settings)
	for id, monitor := range monitors {
		url := "http://" + monitor + "/monitor/ca_update_EEA"
		update := ca.Updates_EEA[id]
		update_json, err := json.Marshal(update)
		if err != nil {
			log.Fatalf("Failed to marshal update: %v", err)
		}
		_, err = ca.Client.Post(url, "application/json", bytes.NewBuffer(update_json))
		if err != nil {
			fmt.Println("Failed to send update to: ", update.MonitorID)
			fmt.Println(err)
			//fmt.Println(update.FileShare)
		} else {
			fmt.Println("Update sent to ", update.MonitorID)
			//fmt.Println(update.FileShare)
		}

	}
}

func StartCA(id def.CTngID, cryptofile string, settingfile string) {
	newca := NewCA(id, cryptofile, settingfile)
	fmt.Println(newca.CTngID)
	newca.GenerateUpdateEEA()
	//fmt.Println(newca.Updates_EEA[def.CTngID("M1")].Head_rs)
	//fmt.Println(newca.Updates_EEA[def.CTngID("M1")].SRH)
	newca.Send_Update_EEA()
}

func StartCADeter(cryptofile string, settingfile string) {
	for i := 1; i <= 100; i++ {
		id := def.CTngID(fmt.Sprintf("C%d", i))
		StartCA(id, cryptofile, settingfile)
	}
}
