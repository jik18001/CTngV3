package ca

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	def "github.com/jik18001/CTngV3/def"
	rs "github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

func TestCryptoFunctionality(t *testing.T) {
	c1 := NewCA(def.CTngID("L1"), "../def/testconfig.json", "../def/testsettings.json")
	testdata := []byte("test data")
	sig, _ := c1.Sign([]byte(testdata))
	err := c1.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

}

func TestCAEEA(t *testing.T) {
	ca := NewCA(def.CTngID("C1"), "../def/testconfig.json", "../def/testsettings.json")
	if ca.Settings == nil {
		t.Fatal("Settings are nil")
	}

	if ca.Updates_EEA == nil {
		t.Fatal("Updates map is nil")
	}

	if ca.Settings.Distribution_Mode != def.EEA {
		t.Fatal("Erasure Encoding Not Enabled")
	}
	// Load and check settings
	totalBits := ca.Settings.CRV_size
	if totalBits <= 0 {
		t.Fatalf("Invalid total bits in settings: %d", totalBits)
	}

	// Generate updates and check for monitor coverage
	crv_sent := ca.GenerateUpdate()
	monitorIDs := def.GenerateRandomCTngIDs(ca.NumMonitors-ca.Mal, ca.NumMonitors)
	fmt.Println(monitorIDs)
	/*
		monitorIDs := []def.CTngID{
			def.CTngID("M1"), def.CTngID("M2"), def.CTngID("M3"), def.CTngID("M4"), def.CTngID("M5"), def.CTngID("M6"),
		}

			for _, monitorID := range monitorIDs {

				update, exists := ca.Updates_EEA[monitorID]
				if !exists {
					t.Fatalf("Update for Monitor ID %s does not exist", monitorID)
				}

				fmt.Printf("Monitor ID: %s\n", monitorID)
				fmt.Printf("SRH: %+v\n", update.SRH)
				if update.FileShare != nil {
					fmt.Printf("FileShare: %x\n", update.FileShare[:10]) // Print first 10 bytes for brevity
				}
				fmt.Printf("PoI: %+v\n", update.PoI)
				fmt.Println()

			}*/

	// Verify integrity of updates
	for _, monitorID := range monitorIDs {
		update, exists := ca.Updates_EEA[monitorID]
		if exists && update.FileShare != nil {
			updateJSON, err := json.Marshal(update)
			if err != nil {
				t.Errorf("Marshalling Failed")
			}
			err = json.Unmarshal(updateJSON, &update)
			if err != nil {
				t.Errorf("UnMarshalling Failed")
			}
			ok, _ := def.VerifyPOI2(update.Head_rs, update.PoI.Proof, update.FileShare)
			if !ok {
				t.Errorf("Verification Failed")
			}
		}
	}

	fileShares := make([][]byte, ca.NumMonitors)
	for _, monitorID := range monitorIDs {
		update, exists := ca.Updates_EEA[monitorID]
		if exists && update.FileShare != nil {
			idString := monitorID.String()
			index, err := strconv.Atoi(idString[1:])
			if err != nil {
				t.Fatalf("Failed to convert ID string to integer: %v", err)
			}
			index-- // Adjust index to 0-based
			fileShares[index] = update.FileShare
		}
	}

	// Reed-Solomon decode
	dec, err := rs.New(ca.NumMonitors-ca.Mal, ca.Mal)
	if err != nil {
		t.Fatalf("Error initializing Reed-Solomon decoder: %v", err)
	}

	err = dec.Reconstruct(fileShares)
	if err != nil {
		t.Fatalf("Error during Reed-Solomon decoding: %v", err)
	}

	var dataBlocks []merkletree.DataBlock
	for _, share := range fileShares {
		if share != nil {
			dataBlocks = append(dataBlocks, &def.LeafBlock{Content: share})
		}
	}
	// Generate Merkle Tree
	tree, err := def.GenerateMerkleTree(dataBlocks)
	if err != nil {
		t.Fatalf("Merkle Tree Generation Error: %v", err)
	}
	rootHash := def.GenerateRootHash(tree)

	update, _ := ca.Updates_EEA[monitorIDs[0]]
	ok := reflect.DeepEqual(rootHash, update.Head_rs)
	if !ok {
		t.Errorf("Roothash verification Failed")
	}

	var dcrv []byte
	for _, share := range fileShares[:ca.NumMonitors-ca.Mal] {
		if share != nil {
			dcrv = append(dcrv, share...) // Reconstruct the DCRV from the first 5 data shares only
		}
	}
	crv_received := def.RemovePadding(dcrv)
	crv_received = append(crv_received, 0)
	if !reflect.DeepEqual(crv_received, crv_sent) {
		fmt.Println(len(crv_received))
		fmt.Println(len(crv_sent))
		t.Errorf("DCRV reconstruction failed")
	}
}
