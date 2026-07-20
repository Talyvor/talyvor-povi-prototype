package povi

import (
	"bytes"
	"crypto/sha256"
)

// Minimal binary Merkle tree over pre-hashed leaves, stdlib-only.
//
// Convention: when a level has an odd number of nodes, the last node is
// duplicated (hashed with itself) to form its parent. This is the common
// Bitcoin-style convention; it is fine for a cost-measurement prototype.
//
// NOTE: a production tree should domain-separate leaf vs internal hashes
// (e.g. prefix 0x00 for leaves, 0x01 for internal nodes) to block
// second-preimage attacks. We omit that here because it does not change the
// cost profile we are measuring, only the security hardening.

// MerkleTree stores every level. levels[0] is the leaves; the final level is
// a single-element slice holding the root.
type MerkleTree struct {
	levels [][][]byte
}

// ProofNode is one sibling on an authentication path.
type ProofNode struct {
	Hash    []byte
	IsRight bool // true if this sibling sits to the RIGHT of the running hash
}

func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// BuildMerkleTree builds a tree bottom-up from the given leaf hashes.
func BuildMerkleTree(leaves [][]byte) *MerkleTree {
	if len(leaves) == 0 {
		panic("BuildMerkleTree: need at least one leaf")
	}
	levels := [][][]byte{leaves}
	cur := leaves
	for len(cur) > 1 {
		next := make([][]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 < len(cur) {
				next = append(next, hashPair(cur[i], cur[i+1]))
			} else {
				next = append(next, hashPair(cur[i], cur[i])) // duplicate last
			}
		}
		levels = append(levels, next)
		cur = next
	}
	return &MerkleTree{levels: levels}
}

// Root returns the Merkle root (32 bytes).
func (t *MerkleTree) Root() []byte {
	top := t.levels[len(t.levels)-1]
	return top[0]
}

// Depth is the number of sibling hashes on any authentication path.
func (t *MerkleTree) Depth() int {
	return len(t.levels) - 1
}

// AuthPath returns the sibling hashes from leaf `index` up to (not including)
// the root, ordered leaf-to-root.
func (t *MerkleTree) AuthPath(index int) []ProofNode {
	path := make([]ProofNode, 0, t.Depth())
	idx := index
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]
		var siblingIdx int
		var siblingIsRight bool
		if idx%2 == 0 {
			siblingIdx = idx + 1
			siblingIsRight = true
		} else {
			siblingIdx = idx - 1
			siblingIsRight = false
		}
		if siblingIdx >= len(nodes) {
			// odd level: node was duplicated, sibling is itself (to the right).
			siblingIdx = idx
			siblingIsRight = true
		}
		sib := make([]byte, len(nodes[siblingIdx]))
		copy(sib, nodes[siblingIdx])
		path = append(path, ProofNode{Hash: sib, IsRight: siblingIsRight})
		idx /= 2
	}
	return path
}

// VerifyAuthPath recomputes the root from a leaf hash and its auth path and
// checks it equals the claimed root.
func VerifyAuthPath(leafHash []byte, path []ProofNode, root []byte) bool {
	cur := leafHash
	for _, node := range path {
		if node.IsRight {
			cur = hashPair(cur, node.Hash)
		} else {
			cur = hashPair(node.Hash, cur)
		}
	}
	return bytes.Equal(cur, root)
}
