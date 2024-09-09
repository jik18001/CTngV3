package def

import (
	"crypto/rand"

	merkletree "github.com/txaty/go-merkletree"
)

type LeafBlock struct {
	Content []byte
}

func (c *LeafBlock) Serialize() ([]byte, error) {
	return c.Content, nil
}

func GenerateRandBlocks(size int) (blocks []merkletree.DataBlock) {
	for i := 0; i < size; i++ {
		block := &LeafBlock{
			Content: make([]byte, 100),
		}
		_, err := rand.Read(block.Content)
		HandleError(err, "GenerateRandBlocks")
		blocks = append(blocks, block)
	}
	return
}

func GenerateMerkleTree(blocks []merkletree.DataBlock) (*merkletree.MerkleTree, error) {
	// Assuming the DataBlock type implements the Content interface, including the Serialize method.
	tree, err := merkletree.New(nil, blocks)
	return tree, err
}

func GenerateRootHash(tree *merkletree.MerkleTree) []byte {
	return tree.Root
}

func GeneratePOI(blocks []merkletree.DataBlock, index int) (PoI, error) {
	// create a Merkle Tree config and set mode to tree building
	config := &merkletree.Config{
		Mode: merkletree.ModeTreeBuild,
	}
	tree, err := merkletree.New(config, blocks)
	proof, err := tree.Proof(blocks[index])
	return PoI{proof}, err
}

func VerifyPOI(sth STH, poi PoI, data []byte) (bool, error) {
	ok, err := merkletree.Verify(&LeafBlock{Content: data}, poi.Proof, sth.Head, nil)
	return ok, err
}

func VerifyPOI2(rootHash []byte, poi *merkletree.Proof, data []byte) (bool, error) {
	ok, err := merkletree.Verify(&LeafBlock{Content: data}, poi, rootHash, nil)
	return ok, err
}
