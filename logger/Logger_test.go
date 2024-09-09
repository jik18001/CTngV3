package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"testing"

	def "github.com/jik18001/CTngV3/def"
	rs "github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

func TestLoggerCryptoFunctionality(t *testing.T) {
	l1 := NewLogger(def.CTngID("L1"), "../def/testconfig.json", "../def/testsettings.json")
	// Example test data
	testdata := []byte("test data")
	sig, _ := l1.Sign([]byte(testdata))
	err := l1.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestLoggerEEA(t *testing.T) {
	logger := NewLogger(def.CTngID("L1"), "../def/testconfig.json", "../def/testsettings.json")
	CertificateSize := logger.Settings.Certificate_size
	logger.GenerateUpdate()
	monitorIDs := def.GenerateRandomCTngIDs(logger.NumMonitors-logger.Mal, logger.NumMonitors)
	for _, monitorID := range monitorIDs {
		update, exists := logger.Updates_EEA[monitorID]
		if !exists {
			t.Fatalf("Update for Monitor ID %s does not exist", monitorID)
		}

		fmt.Printf("Monitor ID: %s\n", monitorID)
		fmt.Printf("STH: %+v\n", update.STH)
		if update.FileShare != nil {
			fmt.Printf("FileShare: %x\n", update.FileShare[:10]) // Print first 10 bytes for brevity
		}
		fmt.Printf("PoI: %+v\n", update.PoI)
		fmt.Println()
	}

	// Collect the file shares
	fileShares := make([][]byte, logger.NumMonitors) // Create a slice to hold up to 8 shares
	for _, monitorID := range monitorIDs {
		update, exists := logger.Updates_EEA[monitorID]
		if exists && update.FileShare != nil {
			/*
				update_json, err := json.Marshal(update)
				if err != nil {
					t.Errorf("Marshalling Failed")
				}
				err = json.Unmarshal(update_json, &update)
				if err != nil {
					t.Errorf("UnMarshalling Failed")
				}*/
			// Serialization using json.Encoder
			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			err := encoder.Encode(update)
			if err != nil {
				t.Errorf("Encoding failed: %v", err)
			}

			// Deserialization using json.Decoder
			decoder := json.NewDecoder(&buffer)
			err = decoder.Decode(&update)
			if err != nil {
				t.Errorf("Decoding failed: %v", err)
			}
			ok, _ := def.VerifyPOI2(update.Head_rs, update.PoI.Proof, update.FileShare)
			if !ok {
				t.Errorf("Verification Failed")
			}
			idString := monitorID.String()
			index, err := strconv.Atoi(idString[1:])
			if err != nil {
				log.Fatalf("Failed to convert ID string to integer: %v", err)
			}
			index-- // Adjust index to 0-based
			fileShares[index] = update.FileShare
		}
	}

	// Reed-Solomon decode
	fmt.Println(logger.NumMonitors-logger.Mal, logger.Mal)
	dec, err := rs.New(logger.NumMonitors-logger.Mal, logger.Mal)
	if err != nil {
		log.Fatalf("Error initializing Reed-Solomon decoder: %v", err)
	}

	err = dec.Reconstruct(fileShares)
	if err != nil {
		log.Fatalf("Error during Reed-Solomon decoding: %v", err)
	}
	var dataBlocks []merkletree.DataBlock
	for i := range fileShares[:(logger.NumMonitors - logger.Mal)] {
		for j := 0; j < len(fileShares[i]); j += CertificateSize {
			end := j + CertificateSize
			if end > len(fileShares[i]) {
				end = len(fileShares[i])
			}
			dataBlocks = append(dataBlocks, &def.LeafBlock{Content: fileShares[i][j:end]})
		}
	}
	// Generate Merkle Tree
	tree, err := def.GenerateMerkleTree(dataBlocks)
	def.HandleError(err, "MT Generation")
	rootHash := def.GenerateRootHash(tree)

	update, _ := logger.Updates_EEA[monitorIDs[0]]
	fmt.Println(rootHash)
	fmt.Println(update.Head_cert)
	ok := reflect.DeepEqual(rootHash, update.Head_cert)
	if !ok {
		fmt.Println(rootHash)
		fmt.Println(update.STH.Head)
		t.Errorf("STH Verification Failed")
	}
}
