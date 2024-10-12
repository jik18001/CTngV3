package def

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	bls "github.com/herumi/bls-go-binary/bls"
)

type BlsPublicMap map[CTngID]bls.PublicKey
type BlsPrivateMap map[CTngID]bls.SecretKey

type BLSThresholdSignatures interface {
	GenerateThresholdKeypairs([]CTngID, int) ([]bls.ID, BlsPublicMap, BlsPrivateMap, error)
	ThresholdSign(msg string, secret bls.SecretKey) (SigFragment, error)
	ThresholdAggregate([]SigFragment, int) (ThresholdSig, error)
}

/*
// Generate mappings of IDs to Private Keys and Public Keys Based on a config's parameters
func GenerateThresholdKeypairs(entities []CTngID, threshold int) ([]bls.ID, BlsPublicMap, BlsPrivateMap, []bls.PublicKey, error) {
	if threshold < 2 {
		return nil, nil, nil, nil, errors.New("Threshold must be greater than 1")
	}
	//ids for n entities
	n := len(entities)
	ids := make([]bls.ID, n)
	mainSecrets := make([]bls.SecretKey, threshold)
	privs := make(BlsPrivateMap)
	pubs := make(BlsPublicMap)
	sec := new(bls.SecretKey)
	//sec.SetByCSPRNG()

	mainSecrets = sec.GetMasterSecretKey(threshold)
	mpk := bls.GetMasterPublicKey(mainSecrets)
	//Generate all IDs and Keypairs.
	for i := 0; i < n; i++ {
		// blsIDs should be derived from the CTngIDs. In this case, we use hex string conversion.
		// Note that blsIDs are only used when keys are generated, not sure when else.
		sec := new(bls.SecretKey)
		ids[i] = *entities[i].BlsID()
		sec.Set(mainSecrets, &ids[i])
		privs[entities[i]] = *sec
		pubs[entities[i]] = *sec.GetPublicKey()
		//Generate all the PublicKeys (for distribution to individual entities later)
	}
	// None of the above functions return errors. Instead they panic.
	// If cryptography information fails to generate then we cannot proceed.
	return ids, pubs, privs, mpk, nil
}*/

func GenerateThresholdKeypairs(entities []CTngID, threshold int) ([]bls.ID, BlsPublicMap, BlsPrivateMap, []bls.PublicKey, error) {
	if threshold < 2 {
		return nil, nil, nil, nil, errors.New("Threshold must be greater than 1")
	}

	n := len(entities)
	ids := make([]bls.ID, n)                        // Unique IDs for the entities
	mainSecrets := make([]bls.SecretKey, threshold) // Master secret keys for the threshold
	privs := make(BlsPrivateMap)                    // Private key map for each participant
	pubs := make(BlsPublicMap)                      // Public key map for each participant
	sec := new(bls.SecretKey)                       // Secret key instance
	mpk := make([]bls.PublicKey, threshold)         // Master public key array

	// Step 1: Generate "threshold" number of master secret keys
	mainSecrets = sec.GetMasterSecretKey(threshold)

	// Step 2: Generate master public keys from the master secrets
	mpk = bls.GetMasterPublicKey(mainSecrets)

	// Step 3: Generate secret shares for all participants using Shamir's Secret Sharing
	for i := 0; i < n; i++ {
		// Each participant gets a unique ID
		ids[i] = *entities[i].BlsID()

		// Generate the secret share for the participant using their ID
		sec.Set(mainSecrets, &ids[i])

		// Store the secret share in the private key map
		privs[entities[i]] = *sec

		// Generate and store the public key for each participant
		pubs[entities[i]] = *sec.GetPublicKey()
	}

	// Return the IDs, public/private key mappings, and master public key
	return ids, pubs, privs, mpk, nil
}

// ThresholdSign will generate a signature fragment for the given message.
func ThresholdSign(msg string, sec *bls.SecretKey, SelfID CTngID) SigFragment {
	// Simple: sign the message using the secret key and package with the ID.
	sig := sec.Sign(msg)
	return SigFragment{
		Sign: sig,
		ID:   SelfID,
	}
}

// Aggregate signature Fragments into a ThresholdSig.
func ThresholdAggregate(sigs []SigFragment, threshold int) (ThresholdSig, error) {
	var aggregate = ThresholdSig{
		IDs:  make([]CTngID, len(sigs)),
		Sign: new(bls.Sign),
	}
	if len(sigs) < threshold {
		return aggregate, errors.New("Not enough signatures to aggregate")
	}
	// create list of []bls.Sign for aggregate.
	realSigs := make([]bls.Sign, len(sigs))
	for i := range sigs {
		aggregate.IDs[i] = sigs[i].ID
		realSigs[i] = *sigs[i].Sign
	}
	// Sort the ordering of IDs for consistency.
	sort.Sort(CTngIDs(aggregate.IDs))
	aggregate.Sign.Aggregate(realSigs)
	return aggregate, nil
}

// Verify an aggregated threshold signature against the message and the public keys
func (sig ThresholdSig) Verify(msg string, pubs *BlsPublicMap) bool {
	// Construct the list of public keys
	pubList := make([]bls.PublicKey, len(sig.IDs))
	for i := range sig.IDs {
		pubList[i] = (*pubs)[sig.IDs[i]]
	}
	//agregates the public signatures of the signers of the message and then verifies the message against that aggregated signature.
	return sig.Sign.FastAggregateVerify(pubList, []byte(msg))
}

func (sig ThresholdSig) MasterVerify(msg string, pubs []bls.PublicKey) bool {
	return sig.Sign.FastAggregateVerify(pubs, []byte(msg))
}

// Given a message and a public key mapping, verify the signature runs.
func (f SigFragment) Verify(msg string, pubs *BlsPublicMap) bool {
	pub := (*pubs)[f.ID]
	return (f.Sign).Verify(&pub, msg)
}

func init() {
	// The init function needs to be immediately called upon import.
	x := bls.BLS12_381
	bls.Init(x)
}

// Serialization of these fields for transportation.
// Note that this is an inconvenience of this specific BLS library.
// Normally, we would be able to just Marshal/Unmarshal a mapping.
// This is likely an inconvenience of using the C implementation of BLS.
func (p *BlsPublicMap) Serialize() map[string][]byte {
	serialized := make(map[string][]byte)
	for id, key := range *p {
		serialized[id.String()] = (&key).Serialize()
	}
	return serialized
}

func (p *BlsPrivateMap) Serialize() map[string][]byte {
	serialized := make(map[string][]byte)
	for id, key := range *p {
		serialized[id.String()] = (&key).Serialize()
	}
	return serialized
}

// Deserialize takes the serialized version of the public map, deserializes it, and puts it in p.
// p should be allocated space for the BLSPublicMap to be stored.
func (p *BlsPublicMap) Deserialize(serialized map[string][]byte) error {
	var err error
	blsPub := new(bls.PublicKey)
	for key, val := range serialized {
		err = blsPub.Deserialize(val)
		if err != nil {
			return err
		}
		(*p)[CTngID(key)] = *blsPub
	}
	return nil
}

func (p *BlsPrivateMap) Deserialize(serialized map[string][]byte) error {
	var err error
	blsPub := new(bls.SecretKey)
	for key, val := range serialized {
		err = blsPub.Deserialize(val)
		if err != nil {
			return err
		}
		(*p)[CTngID(key)] = *blsPub
	}
	return nil
}

type SigFragment struct {
	Sign *bls.Sign
	ID   CTngID
}

// Convert a SigFragment to a string.
// Signatures need to be turned into strings to be stored in Gossip Objects.
// To convert back, use SigFragmentFromString().
func (s SigFragment) String() string {
	return fmt.Sprintf(`{"sign":"%s","id":"%s"}`, s.Sign.SerializeToHexStr(), s.ID.String())
}

// Returns a signature fragment generated from a string.
func SigFragmentFromString(str string) (SigFragment, error) {
	s := new(SigFragment)
	s.Sign = new(bls.Sign)
	stringmap := make(map[string]string)
	err := json.Unmarshal([]byte(str), &stringmap)
	if err != nil {
		return *s, err
	}
	err = s.Sign.DeserializeHexStr(stringmap["sign"])
	if err != nil {
		return *s, err
	}
	s.ID = CTngID(stringmap["id"])
	return *s, err
}

type ThresholdSig struct {
	IDs  []CTngID // Users must know the list of IDs that created the theshold signature to verify.
	Sign *bls.Sign
}

func (t ThresholdSig) String() (string, error) {
	ids := make([]string, len(t.IDs))
	for i, id := range t.IDs {
		ids[i] = string(id)
	}
	idsStr, err := json.Marshal(ids)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`{"sign":"%s", "ids":%s}`, t.Sign.SerializeToHexStr(), idsStr), nil
}

func ThresholdSigFromString(str string) (ThresholdSig, error) {
	t := new(ThresholdSig)
	// Capture the fields in the struct generated below
	tstr := struct {
		Sign string
		IDs  []string
	}{}
	err := json.Unmarshal([]byte(str), &tstr)
	if err != nil {
		return *t, err
	}
	// Convert the IDS to CTngIDs
	t.IDs = make([]CTngID, len(tstr.IDs))
	for i, id := range tstr.IDs {
		t.IDs[i] = CTngID(id)
	}
	t.Sign = new(bls.Sign)
	err = t.Sign.DeserializeHexStr(tstr.Sign)
	return *t, err
}
