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

// output the dcrv just for testing
func (ca *CA) GenerateUpdateEEA() []byte {
	//Load CA related Settings
	//slightly adjust the size so that RS encoding can work properly
	// final_size = totalbits/8 + 8 needs to be divisible by ca.NumMonitors-ca.mal

	totalBits := ca.Settings.CRV_size
	density := ca.Settings.Revocation_ratio
	mode := ca.Settings.Distribution_Mode
	// Initialize Reed-Solomon encoder
	fmt.Println("Number of monitors: ", ca.NumMonitors, " Number of data shares: ", ca.NumMonitors-ca.Mal, " Number of parity shares: ", ca.Mal)
	enc, err := rs.New(ca.NumMonitors-ca.Mal, ca.Mal)
	if err != nil {
		log.Fatalf("Error initializing Reed-Solomon encoder: %v", err)
	}

	// Generate a random compressed DCRV
	dcrv := GenerateRandomCompressedDCRV(totalBits, density)
	// Divide the DCRV into equal parts for each monitor
	dataSize := len(dcrv) / (ca.NumMonitors - ca.Mal)
	fmt.Println("length of DCRV post-compression", len(dcrv))
	fmt.Println("datasize of rs-encoded post-compression DCRV: ", dataSize)
	if len(dcrv)%dataSize != 0 {
		dataSize++ // Adjust dataSize to ensure all data is covered
	}
	data := make([][]byte, ca.NumMonitors)
	for i := range data[:ca.NumMonitors-ca.Mal] {
		start := i * dataSize
		end := start + dataSize
		if end > len(dcrv) {
			end = len(dcrv)
		}
		data[i] = dcrv[start:end]
	}

	// Padding for data alignment with number of monitors
	for i := range data {
		if len(data[i]) < dataSize {
			padded := make([]byte, dataSize)
			copy(padded, data[i])
			data[i] = padded
		}
	}

	// Encode the data if the mode is Reedsolomn
	if mode == def.EEA {
		err := enc.Encode(data)
		def.HandleError(err, "RS Encoding error")
		// Create a slice to hold the encoded data for each monitor
		var RSdataBlocks []merkletree.DataBlock
		for i := range data {
			RSdataBlocks = append(RSdataBlocks, &def.LeafBlock{Content: data[i]})
		}

		// Generate the second Merkle Tree
		RStree, err := def.GenerateMerkleTree(RSdataBlocks)
		def.HandleError(err, "RS Merkle Tree Generation")
		rootHashRS := def.GenerateRootHash(RStree)
		SRHEEA := ca.GenerateSRHEEA(dcrv, dcrv, rootHashRS)
		//sthRS := ca.GenerateSTH(rootHashRS, totalBits)
		originalLen := len(dcrv)
		for id, update := range ca.Updates_EEA {
			index := def.GetIndex(id)
			//fmt.Println(index, idString)
			update.SRH = *SRHEEA
			update.FileShare = data[index]
			poi, _ := def.GeneratePOI(RStree, RSdataBlocks, index)
			update.Head_rs = rootHashRS
			update.PoI = poi
			update.OriginalLen = originalLen // Set the original length here
			ca.Updates_EEA[id] = update      // Store the modified update back
		}
		return dcrv
	}
	// only simulating one period
	SRH := ca.GenerateSRH(dcrv, dcrv)
	for _, update := range ca.Updates {
		update.SRH = *SRH
		update.File = update.File
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
	newca.GenerateUpdateEEA()
	//fmt.Println(newca.Updates_EEA[def.CTngID("M1")].Head_rs)
	//fmt.Println(newca.Updates_EEA[def.CTngID("M1")].SRH)
	newca.Send_Update_EEA()
}
