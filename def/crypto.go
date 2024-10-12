package def

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	bls "github.com/herumi/bls-go-binary/bls"
)

type GlobalCrypto struct {
	Total           int
	Threshold       int
	DSS_public_map  RSAPublicMap
	DSS_private_map RSAPrivateMap
	TSS_public_map  BlsPublicMap
	TSS_private_map BlsPrivateMap
	DSS_Scheme      string
	TSS_Scheme      string
	HashScheme      HashAlgorithm
}

func CTngKeyGen(Lnum int, Cnum int, Mnum int, Threshold int) *GlobalCrypto {
	Loggers := make([]CTngID, Lnum)
	for i := 0; i < Lnum; i++ {
		Loggers[i] = CTngID(fmt.Sprintf("L%d", i+1))
	}

	CAs := make([]CTngID, Cnum)
	for i := 0; i < Cnum; i++ {
		CAs[i] = CTngID(fmt.Sprintf("C%d", i+1))
	}

	Monitors := make([]CTngID, Mnum)
	for i := 0; i < Mnum; i++ {
		Monitors[i] = CTngID(fmt.Sprintf("M%d", i+1))
	}

	RSAPublicMap := make(RSAPublicMap)
	RSAPrivateMap := make(RSAPrivateMap)
	BLSPublicMap := make(BlsPublicMap)
	BlsPrivateMap := make(BlsPrivateMap)

	// Populate the RSA maps with generated keys for CAs
	for _, ca := range CAs {
		privateKey, err := NewRSAPrivateKey()
		if err != nil {
			HandleError(err, "CTngKeyGen")
			continue
		}
		publicKey, _ := GetPublicKey(privateKey)
		RSAPrivateMap[ca] = *privateKey
		RSAPublicMap[ca] = *publicKey
	}

	// Populate the RSA maps with generated keys for Loggers
	for _, logger := range Loggers {
		privateKey, err := NewRSAPrivateKey()
		if err != nil {
			HandleError(err, "CTngKeyGen")
			continue
		}
		publicKey, _ := GetPublicKey(privateKey)
		RSAPrivateMap[logger] = *privateKey
		RSAPublicMap[logger] = *publicKey
	}
	// Threshold KeyGen for the Monitors
	_, BLSPublicMap, BlsPrivateMap, _, _ = GenerateThresholdKeypairs(Monitors, Threshold)

	Total := Mnum

	cryptofile := GlobalCrypto{
		Total:           Total,
		Threshold:       Threshold,
		DSS_public_map:  RSAPublicMap,
		DSS_private_map: RSAPrivateMap,
		TSS_public_map:  BLSPublicMap,
		TSS_private_map: BlsPrivateMap,
		DSS_Scheme:      "rsa",
		TSS_Scheme:      "bls",
		HashScheme:      SHA256,
	}
	return &cryptofile
}

type StoredCrypto struct {
	Total           int
	Threshold       int
	DSS_public_map  RSAPublicMap
	DSS_private_map RSAPrivateMap
	TSS_public_map  map[string][]byte
	TSS_private_map map[string][]byte
	DSS_Scheme      string
	TSS_Scheme      string
	HashScheme      int
}

func EncodeCrypto(c *GlobalCrypto) *StoredCrypto {
	stored := new(StoredCrypto)
	stored = &StoredCrypto{
		Total:           c.Total,
		Threshold:       c.Threshold,
		DSS_public_map:  c.DSS_public_map,
		DSS_private_map: c.DSS_private_map,
		DSS_Scheme:      c.DSS_Scheme,
		TSS_Scheme:      c.TSS_Scheme,
		HashScheme:      int(c.HashScheme),
	}
	stored.TSS_public_map = (&c.TSS_public_map).Serialize()
	stored.TSS_private_map = (c.TSS_private_map).Serialize()
	return stored
}

func DecodeCrypto(c *StoredCrypto) (*GlobalCrypto, error) {
	global := new(GlobalCrypto)
	global = &GlobalCrypto{
		Total:           c.Total,
		Threshold:       c.Threshold,
		DSS_public_map:  c.DSS_public_map,
		DSS_private_map: c.DSS_private_map,
		DSS_Scheme:      c.DSS_Scheme,
		TSS_Scheme:      c.TSS_Scheme,
		HashScheme:      HashAlgorithm(c.HashScheme),
		TSS_public_map:  make(BlsPublicMap),
		TSS_private_map: make(BlsPrivateMap),
	}
	err := (&global.TSS_public_map).Deserialize(c.TSS_public_map)
	if err != nil {
		return global, err
	}
	err = (&global.TSS_private_map).Deserialize(c.TSS_private_map)
	if err != nil {
		return global, err
	}
	return global, nil
}

type GlobalCryptoInterface interface {
	Hash([]byte) ([]byte, error)
	Sign([]byte) (RSASig, error)
	Verify([]byte, RSASig) error
	ThresholdSign(string) (SigFragment, error)
	ThresholdAggregate([]SigFragment) (ThresholdSig, error)
	ThresholdVerify(string, ThresholdSig) error
	FragmentVerify(string, SigFragment) error
}

// Hash a message using the configured hash scheme.
func (c *GlobalCrypto) Hash(msg []byte) ([]byte, error) {
	if c.HashScheme == SHA256 {
		return GenerateSHA256(msg)
	} else if c.HashScheme == MD5 {
		return GenerateMD5(msg)
	}
	return nil, errors.New("Hash Scheme not supported")
}

// Sign a message using the configured "normal signature" scheme.
// Note: This is not a threshold signature/threshold signature fragment.
func (c *GlobalCrypto) Sign(msg []byte, id CTngID) (RSASig, error) {
	if c.DSS_Scheme == "rsa" {
		sk := c.DSS_private_map[id]
		return RSASign(msg, &sk, id)
	}
	return RSASig{}, errors.New("Sign Scheme not supported")
}

// Verify a message using the configured "normal signature" scheme, and the stored public keys.
func (c *GlobalCrypto) Verify(msg []byte, sig RSASig) error {
	if c.DSS_Scheme == "rsa" {
		pub := c.DSS_public_map[sig.ID]
		//fmt.Println("PublicKey Found: ",pub)
		return RSAVerify(msg, sig, &pub)
	}
	return errors.New("Sign Scheme not supported")
}

// Sign a message to make a keyfragment using the configured "threshold signature" scheme.
func (c *GlobalCrypto) ThresholdSign(msg string, id CTngID) (SigFragment, error) {
	if c.TSS_Scheme == "bls" {
		sk := c.TSS_private_map[id]
		return ThresholdSign(msg, &sk, id), nil
	}
	// Other threshold schemes could go Here
	return SigFragment{}, errors.New("Threshold Scheme not supported")
}

// Aggregate a list of threshold signature fragments to make a threshold signature.
func (c *GlobalCrypto) ThresholdAggregate(sigs []SigFragment) (ThresholdSig, error) {
	if c.TSS_Scheme == "bls" {
		sig, err := ThresholdAggregate(sigs, c.Threshold)
		if err != nil {
			return ThresholdSig{}, err
		} else {
			return sig, nil
		}
	}
	return ThresholdSig{}, errors.New("Threshold Scheme not supported")
}

// Verify a threshold signature using the configured "threshold signature" scheme, and the stored public keys.
// Uses the keys stored in the GlobalCrypto struct to verify the signature.
func (c *GlobalCrypto) ThresholdVerify(msg string, sig ThresholdSig) error {
	if c.TSS_Scheme == "bls" {
		if sig.Verify(msg, &c.TSS_public_map) {
			return nil
		} else {
			return errors.New("Threshold Signature Verification Failed")
		}
	}
	return errors.New("Threshold Scheme not supported")
}

// Verify the validity of a single signature fragment using the configured "threshold signature" scheme.
// Uses the keys stored in the GlobalCrypto struct to verify the signature.
func (c *GlobalCrypto) FragmentVerify(msg string, sig SigFragment) error {
	if c.TSS_Scheme == "bls" {
		if sig.Verify(msg, &c.TSS_public_map) {
			return nil
		} else {
			return errors.New("Signature Fragment Verification Failed")
		}
	}
	return errors.New("Threshold Scheme not supported")
}

// Generic Ids are URLS.
type CTngID string

func (id CTngID) String() string {
	return string(id)
}

// BLS IDs should be derived directly from the CTngID.
// This essentially maps every CTngID to a unique BLS ID.
func (id CTngID) BlsID() *bls.ID {
	b := new(bls.ID)
	err := b.SetHexString(hex.EncodeToString([]byte(id)))
	// This shouldn't happen if IDs are being used appropriately, so I think a panic is warranted.
	if err != nil {
		panic(err)
	}
	return b
}

// The reverse of CTngID.BlsID().
func CTngIDfromBlsID(blsid *bls.ID) (CTngID, error) {
	id, err := hex.DecodeString(blsid.SerializeToHexStr())
	return CTngID(id), err
}

// Implemented functions for sorting
// The following types are neccessary for the sorting of CTng IDs.
// We sort CTngIds in aggregated signatures for consistency when transporting.
// Otherwise, payloads which contain the CTng IDs may not be consistent.
type CTngIDs []CTngID

func (ids CTngIDs) Less(i, j int) bool {
	return string(ids[i]) < string(ids[j])
}
func (ids CTngIDs) Len() int {
	return len(ids)
}
func (ids CTngIDs) Swap(i, j int) {
	ids[i], ids[j] = ids[j], ids[i]
}

// Enum is an unsigned integer.
type Enum uint64

func GetIndex(id CTngID) int {
	idString := id.String()
	index, _ := strconv.Atoi(idString[1:])
	index-- // Adjust index to 0-based
	return index
}
