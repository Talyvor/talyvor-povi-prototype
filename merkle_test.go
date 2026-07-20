package povi

import (
	"crypto/sha256"
	"testing"
)

// leaf builds a leaf hash the same way the tree does, so tests can construct inputs.
func leaf(b byte) []byte {
	h := sha256.Sum256([]byte{b})
	return h[:]
}

// makeLeaves returns n distinct leaf hashes.
func makeLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		out[i] = h[:]
	}
	return out
}

func TestMerkleEveryAuthPathRecomputesRoot(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 100, 1000} {
		leaves := makeLeaves(n)
		tree := BuildMerkleTree(leaves)
		root := tree.Root()
		for i := 0; i < n; i++ {
			path := tree.AuthPath(i)
			if !VerifyAuthPath(leaves[i], path, root) {
				t.Fatalf("n=%d: auth path for leaf %d did not recompute root", n, i)
			}
		}
	}
}

func TestMerkleTamperedLeafFailsVerification(t *testing.T) {
	leaves := makeLeaves(1000)
	tree := BuildMerkleTree(leaves)
	root := tree.Root()

	path := tree.AuthPath(42)
	// A tampered leaf value must not verify against the honest root.
	tampered := leaf(0xFF)
	if VerifyAuthPath(tampered, path, root) {
		t.Fatal("tampered leaf incorrectly verified against honest root")
	}
}

func TestMerkleTamperedRootFailsVerification(t *testing.T) {
	leaves := makeLeaves(256)
	tree := BuildMerkleTree(leaves)
	badRoot := leaf(0xAB)

	path := tree.AuthPath(7)
	if VerifyAuthPath(leaves[7], path, badRoot) {
		t.Fatal("honest leaf incorrectly verified against tampered root")
	}
}

func TestMerkleDistinctLeavesGiveDistinctRoots(t *testing.T) {
	a := BuildMerkleTree(makeLeaves(100)).Root()
	leaves := makeLeaves(100)
	leaves[50] = leaf(0x01) // change one leaf
	b := BuildMerkleTree(leaves).Root()
	if string(a) == string(b) {
		t.Fatal("changing one leaf did not change the root")
	}
}
