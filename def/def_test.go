package def

import (
	"bytes"
	"encoding/asn1"
	"flag"
	"fmt"
	"math/rand"
	"testing"

	"github.com/klauspost/reedsolomon"
	merkletree "github.com/txaty/go-merkletree"
)

// For randomized signature aggregation testing
func shuffleSigs(sigs *[]SigFragment) {
	rand.Shuffle(len(*sigs), func(i, j int) {
		(*sigs)[i], (*sigs)[j] = (*sigs)[j], (*sigs)[i]
	})
}

func confirmNil(t *testing.T, err error) {
	if err != nil {
		t.Errorf("%s", err.Error())
	}
}

func TestMerkleTreeFunctions(t *testing.T) {
	// Create a slice of DataBlocks
	dataBlocks := []merkletree.DataBlock{
		&LeafBlock{Content: []byte("block1")},
		&LeafBlock{Content: []byte("block2")},
		&LeafBlock{Content: []byte("block3")},
	}

	// Generate Merkle Tree
	tree, err := GenerateMerkleTree(dataBlocks)
	if err != nil {
		t.Errorf("Failed to generate Merkle Tree: %v", err)
	}

	// Generate Root Hash
	rootHash := GenerateRootHash(tree)
	if len(rootHash) == 0 {
		t.Errorf("Failed to generate root hash")
	}

	// Generate POI for the first block
	proof, err := GeneratePOI(tree, dataBlocks, 0)
	if err != nil {
		t.Errorf("Failed to generate Proof of Inclusion: %v", err)
	}

	// Verify POI
	serializedblock, _ := dataBlocks[0].Serialize()
	ok, err := VerifyPOI2(rootHash, proof.Proof, serializedblock)
	if err != nil {
		t.Errorf("Failed to verify Proof of Inclusion: %v", err)
	}
	if !ok {
		t.Errorf("Proof of Inclusion is not valid")
	}
}

func TestRS(t *testing.T) {
	// Create an encoder with 4 data and 7 parity slices.
	enc, err := reedsolomon.New(4, 7)
	if err != nil {
		t.Fatalf("Failed to create encoder: %v", err)
	}

	data := make([][]byte, 11)
	for i := range data {
		data[i] = make([]byte, 50000)
	}
	for i, in := range data[:4] {
		for j := range in {
			in[j] = byte((i + j) & 0xff)
		}
	}

	// Encode the data
	if err := enc.Encode(data); err != nil {
		t.Fatalf("Failed to encode data: %v", err)
	}

	// Verify the data
	ok, err := enc.Verify(data)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !ok {
		t.Error("Verification failed: data is incorrect")
	}

	// Introduce some errors
	data[1] = nil
	data[3] = nil

	// Reconstruct the data
	if err := enc.Reconstruct(data); err != nil {
		t.Errorf("Failed to reconstruct data: %v", err)
	}

	// Verify the data again after reconstruction
	ok, err = enc.Verify(data)
	if err != nil {
		t.Fatalf("Verification after reconstruction failed: %v", err)
	}
	if !ok {
		t.Error("Verification after reconstruction failed: data is incorrect")
	}
}

func TestEncodeASN1AndReedSolomon(t *testing.T) {
	// Step 1: ASN.1 Encode an integer
	Originalinteger := 123456789
	asn1Data, err := asn1.Marshal(Originalinteger)
	if err != nil {
		t.Fatalf("ASN.1 encoding failed: %v", err)
	}

	// Step 2: Pad the data to a specific size (200000 bytes)
	totalSize := 200000
	if len(asn1Data) > totalSize {
		t.Fatalf("Encoded data is unexpectedly larger than total size")
	}
	paddedData := append(asn1Data, bytes.Repeat([]byte{0}, totalSize-len(asn1Data))...)
	fmt.Println(len(paddedData))
	// Step 3: Partition the padded data into 4 parts
	numShards := 4
	numParity := 3
	shardSize := totalSize / numShards
	shards := make([][]byte, numShards+numParity)
	for i := 0; i < numShards; i++ {
		start := i * shardSize
		shards[i] = paddedData[start : start+shardSize]
	}
	for i := 0; i < numParity; i++ {
		shards[i+numShards] = make([]byte, 50000)
	}
	fmt.Println(len(shards[0]))
	fmt.Println(len(shards[1]))
	fmt.Println(len(shards[2]))
	fmt.Println(len(shards[3]))
	// Step 4: Create a Reed-Solomon encoder with 4 data and 3 parity shards
	enc, err := reedsolomon.New(4, 3)
	if err != nil {
		t.Fatalf("Failed to create Reed-Solomon encoder: %v", err)
	}

	// Step 5: Encode shards using Reed-Solomon
	if err := enc.Encode(shards); err != nil {
		t.Fatalf("Reed-Solomon encoding failed: %v", err)
	}

	// Step 6: Verify the data
	ok, err := enc.Verify(shards)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !ok {
		t.Error("Verification failed: data is incorrect")
	}

	// Introduce some errors
	shards[0] = nil
	shards[3] = nil

	// Reconstruct the data
	if err := enc.Reconstruct(shards); err != nil {
		t.Errorf("Failed to reconstruct data: %v", err)
	}

	// Verify the data again after reconstruction
	ok, err = enc.Verify(shards)
	if err != nil {
		t.Fatalf("Verification after reconstruction failed: %v", err)
	}
	if !ok {
		t.Error("Verification after reconstruction failed: data is incorrect")
	}

	// Concatenate the data shards into one buffer
	reconstructedData := bytes.NewBuffer(nil)
	for _, shard := range shards[:numShards] {
		if shard != nil {
			reconstructedData.Write(shard)
		}
	}

	// Decode the ASN.1 integer from the reconstructed data
	var decodedInteger int
	_, err = asn1.Unmarshal(reconstructedData.Bytes(), &decodedInteger)
	if err != nil {
		t.Fatalf("ASN.1 decoding failed: %v", err)
	}

	fmt.Printf("Original integer: %d, Decoded integer after reconstruction: %d\n", Originalinteger, decodedInteger)
}

func TestBLSFunctionality(T *testing.T) {
	entities := []CTngID{
		"a",
		"b",
		"c",
		"d",
		"e",
	}
	n := len(entities)
	threshold := 2

	// First term is list of BLS ids. We now derive the BLS ids from the CTngIDs, so it can be ignored.
	_, pubs, privs, _, err := GenerateThresholdKeypairs(entities, threshold)

	confirmNil(T, err)

	sigs := make([]SigFragment, n)

	data := "Test information for signing"
	wrongData := "Incorrect Information"

	// Have all entities sign the message
	for i := 0; i < n; i++ {
		priv := privs[entities[i]]
		sigs[i] = ThresholdSign(data, &priv, entities[i])
		//secret.Sign will panic() if it fails, not return an error.
	}

	// Verify individual signatures validate
	for i := 0; i < n; i++ {
		if sigs[i].Verify(data, &pubs) == false {
			T.Errorf("Signature %d failed to verify!", i)
		}
	}

	// Verifying a signature with an incorrect public key should fail
	// It does: The test takes work to structure with the current datatypes so I've removed it for now.

	// Verifying incorrect data should fail
	if sigs[0].Verify(wrongData, &pubs) != false {
		T.Errorf("Signature verified incorrect data!")
	}

	// any group of "config.Threshold" signatures can Aggregate the message
	// Shuffle the list, and run a 'sliding door' over it of size threshold.
	shuffleSigs(&sigs)
	for l := 0; l < (n - threshold); l++ {
		r := l + threshold
		//Aggregate first, then confirm the aggregates verify'
		agg, err := ThresholdAggregate(sigs[l:r], threshold)
		confirmNil(T, err)
		if agg.Verify(data, &pubs) == false {
			T.Errorf("Aggregate failed to verify!")
		}
		/*
			if agg.MasterVerify(data, mpk) == false {
				fmt.Println("Master PublicKey:", mpk)
				T.Errorf("mpk Aggregate failed to verify!")
			}*/
		fmt.Println(agg)
		// Provide an incorrect signer and confirm that the aggregate fails to verify
		agg.IDs[0] = sigs[r%n].ID
		if agg.Verify(data, &pubs) != false {
			T.Errorf("Aggregate verified with incorrect signer!")
		}
		// Remove a signer and confirm that the aggregate fails to verify
		agg.IDs = agg.IDs[1:]
		if agg.Verify(data, &pubs) != false {
			T.Errorf("Aggregate verified with insufficient signers!")
		}
	}

}

func TestCryptoconfig(t *testing.T) {
	config := CTngKeyGen(2, 2, 4, 3)
	testCA := CTngID("C1")
	testLogger := CTngID("L2")
	testMonitor1 := CTngID("M1")
	testMonitor2 := CTngID("M2")
	testMonitor3 := CTngID("M3")
	testdata := "signing test"
	sig, _ := config.Sign([]byte(testdata), testCA)
	err := config.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sig, _ = config.Sign([]byte(testdata), testLogger)
	err = config.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag1, _ := config.ThresholdSign(testdata, testMonitor1)
	err = config.FragmentVerify(testdata, sigfrag1)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag2, _ := config.ThresholdSign(testdata, testMonitor2)
	err = config.FragmentVerify(testdata, sigfrag2)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag3, _ := config.ThresholdSign(testdata, testMonitor3)
	err = config.FragmentVerify(testdata, sigfrag3)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	siglist := []SigFragment{sigfrag1, sigfrag2, sigfrag3}
	thresholdsig, _ := config.ThresholdAggregate(siglist)
	err = config.ThresholdVerify(testdata, thresholdsig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestCryptoIO(t *testing.T) {
	newconfig := CTngKeyGen(2, 2, 4, 3)
	storedconfig := EncodeCrypto(newconfig)
	// Write the encoded configuration to a file (handle errors if necessary).
	err := WriteData(storedconfig, "testconfig.json")
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Initialize a new StoredCrypto object.
	restoredconfig := new(StoredCrypto)

	// Load the configuration from the file.
	LoadData(&restoredconfig, "testconfig.json")
	config, err := DecodeCrypto(restoredconfig)
	if err != nil {
		t.Errorf("Decoding failed: %v", err)
	}
	testCA := CTngID("C1")
	testLogger := CTngID("L2")
	testMonitor1 := CTngID("M1")
	testMonitor2 := CTngID("M2")
	testMonitor3 := CTngID("M3")
	testdata := "signing test"
	sig, _ := config.Sign([]byte(testdata), testCA)
	err = config.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sig, _ = config.Sign([]byte(testdata), testLogger)
	err = config.Verify([]byte(testdata), sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag1, _ := config.ThresholdSign(testdata, testMonitor1)
	err = config.FragmentVerify(testdata, sigfrag1)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag2, _ := config.ThresholdSign(testdata, testMonitor2)
	err = config.FragmentVerify(testdata, sigfrag2)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	sigfrag3, _ := config.ThresholdSign(testdata, testMonitor3)
	err = config.FragmentVerify(testdata, sigfrag3)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
	siglist := []SigFragment{sigfrag1, sigfrag2, sigfrag3}
	thresholdsig, _ := config.ThresholdAggregate(siglist)
	err = config.ThresholdVerify(testdata, thresholdsig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestSimulationIO(t *testing.T) {
	num_monitors := 4
	Mal := 2
	num_loggers := 2
	num_cas := 2
	// Generate a new configuration using CTngKeyGen function with specified parameters.
	newconfig := CTngKeyGen(num_loggers, num_cas, num_monitors, Mal+1)

	// Encode the new configuration into a storable format.
	storedconfig := EncodeCrypto(newconfig)

	// Write the encoded configuration to a file and handle any errors.
	err := WriteData(storedconfig, "testconfig.json")
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Define command-line flags for the number of CAs, Loggers, and Monitors.
	num_ca := flag.Int("num_ca", num_cas, "Number of CAs")
	num_logger := flag.Int("num_logger", num_loggers, "Number of Loggers")
	num_monitor := flag.Int("num_monitor", num_monitors, "Number of Monitors")
	mal := flag.Int("mal", Mal, "Number of faulty monitors allowed")

	// Define command-line flags for IP masks and offsets.

	ca_mask := flag.String("ca_mask", "127.0.0.", "CA IP mask")
	ca_offset := flag.Int("ca_offset", 10, "CA IP offset")
	logger_mask := flag.String("logger_mask", "127.0.1.", "Logger IP mask")
	logger_offset := flag.Int("logger_offset", 20, "Logger IP offset")
	monitor_mask := flag.String("monitor_mask", "127.0.2.", "Monitor IP mask")
	monitor_offset := flag.Int("monitor_offset", 30, "Monitor IP offset")

	//deter mask and offset
	/*
		ca_mask := flag.String("ca_mask", "172.30.0.", "CA IP mask")
		ca_offset := flag.Int("ca_offset", 11, "CA IP offset")
		logger_mask := flag.String("logger_mask", "172.30.0.", "Logger IP mask")
		logger_offset := flag.Int("logger_offset", 13, "Logger IP offset")
		monitor_mask := flag.String("monitor_mask", "172.30.0.", "Monitor IP mask")
		monitor_offset := flag.Int("monitor_offset", 34, "Monitor IP offset")
	*/
	// Define command-line flags for starting port number, wait time, and other settings.
	starting_port := flag.Int("starting_port", 8000, "Starting port number")
	update_wait_time := flag.Int("update_wait_time", 5, "Wait time in seconds")
	mature_wait_time := flag.Int("mature_wait_time", 0, "Wait time in seconds")
	response_wait_time := flag.Int("reponse_wait_time", 6, "Wait time in seconds")
	verification_wait_time := flag.Int("verification_wait_time", 22, "Wait time in seconds")
	mud := flag.Int("mud", 60, "Maximum Update Delay (some integer value) in seconds")
	bmode := flag.String("bmode", MIN_WT, "Mode: Min bandwidth or Min wait time")
	//bmode := flag.String("bmode", MIN_BC, "Mode: Min bandwidth or Min wait time")
	dmode := flag.String("dmode", DEFAULT, "Mode: default or EEA")
	//dmode := flag.String("dmode", EEA, "Mode: default or EEA")
	crvsize := flag.Int("CRV_size", 100000000, "CRV_size")
	revocation_ratio := flag.Float64("Revocation_ratio", 0.002, "Revocation_ratio (float)")
	certificate_size := flag.Int("Cerificate_size", 2000, "Size of dummy certificate, in Bytes")
	certificate_per_logger := flag.Int("Certificate_per_logger", 40000, "New certificates per period")

	// Parse the command-line flags.
	flag.Parse()

	// Generate the IP settings template using the parsed flag values.
	settings := Generate_IP_Json_template(
		*num_ca, *num_logger, *num_monitor, *mal,
		*ca_mask, *ca_offset,
		*logger_mask, *logger_offset,
		*monitor_mask, *monitor_offset,
		*starting_port, *update_wait_time, *mature_wait_time, *response_wait_time, *verification_wait_time,
		*mud, *dmode, *bmode, *crvsize, *revocation_ratio, *certificate_size, *certificate_per_logger,
	)

	// Write the generated settings to a file and handle any errors.
	err = WriteData(settings, "testsettings.json")
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
	fmt.Println(GetMonitorURL(*settings))
	fmt.Println(GetIDs('M', *settings))
	fmt.Println(MapIDtoInt(CTngID("C8")))
}
