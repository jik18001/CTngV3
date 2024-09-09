package def

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type RsaSignatures interface {
	NewRSAPrivateKey() (*rsa.PrivateKey, error)
	GetPublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error)
	Sign(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error)
	//Verify returns an error if the signature couldnt be verified.
	Verify(msg []byte, signature []byte, publicKey []byte) error
}

type RSAPublicMap map[CTngID]rsa.PublicKey
type RSAPrivateMap map[CTngID]rsa.PrivateKey

func NewRSAPrivateKey() (*rsa.PrivateKey, error) {
	// 2048 = Specification requirement for RSA keys
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GetPublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error) {
	return &privateKey.PublicKey, nil
}

func RSASign(msg []byte, privateKey *rsa.PrivateKey, id CTngID) (RSASig, error) {
	// SHA256 = Specification Requirement for RSA signatures
	hash, err := GenerateSHA256(msg)
	if err != nil {
		return RSASig{}, err
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	return RSASig{
		Sig: sig,
		ID:  id}, err
}

func RSAVerify(msg []byte, signature RSASig, pub *rsa.PublicKey) error {
	hash, err := GenerateSHA256(msg)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, signature.Sig)
}

// RSASig contains the ID of the signer and the rsa signature.
type RSASig struct {
	Sig []byte
	ID  CTngID
}

// String -> RSASig conversion
func (s RSASig) String() string {
	return fmt.Sprintf(`{"sig":"%s","id":"%s"}`, hex.EncodeToString(s.Sig), s.ID.String())
}

// RSASig -> String conversion
func RSASigFromString(str string) (RSASig, error) {
	stringmap := make(map[string]string)
	sig := new(RSASig)
	err := json.Unmarshal([]byte(str), &stringmap)
	if err != nil {
		return *sig, err
	}
	sig.Sig = make([]byte, hex.DecodedLen(len(stringmap["sig"])))
	_, err = hex.Decode(sig.Sig, []byte(stringmap["sig"]))
	if err != nil {
		return *sig, err
	}
	sig.ID = CTngID(stringmap["id"])
	return *sig, err
}
