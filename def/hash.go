package def

import (
	"crypto"
	_ "crypto/md5"    // For registration side-effect
	_ "crypto/sha1"   // For registration side-effect
	_ "crypto/sha256" // For registration side-effect
	_ "crypto/sha512" // For registration side-effect
	"fmt"
)

type HashInterface interface {
	GenerateMD5(msg []byte) ([]byte, error)
	GenerateSHA256(msg []byte) ([]byte, error)
}

// Function pulled from certificate-transparency-go/tls. Copied because it isn't defined as external in their repo.
func generateHash(algo HashAlgorithm, data []byte) ([]byte, crypto.Hash, error) {
	var hashType crypto.Hash
	switch algo {
	case MD5:
		hashType = crypto.MD5
	case SHA1:
		hashType = crypto.SHA1
	case SHA224:
		hashType = crypto.SHA224
	case SHA256:
		hashType = crypto.SHA256
	case SHA384:
		hashType = crypto.SHA384
	case SHA512:
		hashType = crypto.SHA512
	default:
		return nil, hashType, fmt.Errorf("unsupported Algorithm.Hash in signature: %v", algo)
	}

	hasher := hashType.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, hashType, fmt.Errorf("failed to write to hasher: %v", err)
	}
	return hasher.Sum([]byte{}), hashType, nil
}

// Generates the MD5 hash for the given bits.
func GenerateMD5(data []byte) ([]byte, error) {
	hash, _, err := generateHash(MD5, data)
	return hash, err
}

// Generates the SHA256 hash for the given bits.
func GenerateSHA256(data []byte) ([]byte, error) {
	hash, _, err := generateHash(SHA256, data)
	return hash, err
}

// Enum is an unsigned integer.
//type Enum uint64

// HashAlgorithm enum from RFC 5246 s7.4.1.4.1.
type HashAlgorithm Enum

// HashAlgorithm constants from RFC 5246 s7.4.1.4.1.
const (
	None   HashAlgorithm = 0
	MD5    HashAlgorithm = 1
	SHA1   HashAlgorithm = 2
	SHA224 HashAlgorithm = 3
	SHA256 HashAlgorithm = 4
	SHA384 HashAlgorithm = 5
	SHA512 HashAlgorithm = 6
)

func (h HashAlgorithm) String() string {
	switch h {
	case None:
		return "None"
	case MD5:
		return "MD5"
	case SHA1:
		return "SHA1"
	case SHA224:
		return "SHA224"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", h)
	}
}
