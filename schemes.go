package povi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	mrand "math/rand"
)

// ============================================================================
// Scheme A — Signed Receipt (cheapest, weakest)
//
// The node signs a hash of the request/response metadata with an ed25519 key.
// PROVES:   this key-holder attested to serving this exact response for this
//           request, at this time.
// CANNOT PROVE: that the response really came from the claimed model, or that
//           the computation was done honestly. It is a signed claim, nothing
//           more. A node can sign a fabricated response just as easily.
// ============================================================================

// Receipt is the metadata a node attests to.
type Receipt struct {
	RequestID    string
	PromptHash   []byte
	ResponseHash []byte
	Model        string
	TokenCount   int
	Timestamp    int64
}

// receiptDigest is the deterministic SHA-256 over the receipt fields that gets
// signed. Length-prefixing each field avoids concatenation ambiguity.
func receiptDigest(r Receipt) []byte {
	h := sha256.New()
	writeField := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		h.Write(l[:])
		h.Write(b)
	}
	writeField([]byte(r.RequestID))
	writeField(r.PromptHash)
	writeField(r.ResponseHash)
	writeField([]byte(r.Model))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(r.TokenCount))
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.Timestamp))
	h.Write(n[:])
	return h.Sum(nil)
}

// SignReceipt returns the 64-byte ed25519 signature over the receipt digest.
func SignReceipt(priv ed25519.PrivateKey, r Receipt) []byte {
	return ed25519.Sign(priv, receiptDigest(r))
}

// VerifyReceipt checks the signature against the receipt and public key.
func VerifyReceipt(pub ed25519.PublicKey, r Receipt, sig []byte) bool {
	return ed25519.Verify(pub, receiptDigest(r), sig)
}

// ProofSizeA is the bytes added to a response purely for the proof: the
// signature. The receipt fields (request id, model, token count, ...) are data
// the gateway already holds, so they are not counted as proof overhead.
const ProofSizeA = ed25519.SignatureSize // 64

// ============================================================================
// Scheme B — Merkle-committed execution trace (realistic middle option)
//
// Each of N execution steps produces an intermediate state. We hash every
// state into a leaf, build a Merkle tree, and the proof is the root plus K
// randomly-sampled authentication paths.
// PROVES (probabilistically): the committed trace is internally consistent.
//           Tampering with any one step is caught by a sampled path with
//           probability ~K/N per check; with K samples the chance all tampered
//           steps are missed falls off fast.
// CANNOT PROVE: that the states are the *correct* outputs of an honest model
//           run. A node can commit to a self-consistent but fabricated trace.
// ============================================================================

// SampleB is one revealed leaf and its authentication path.
type SampleB struct {
	Index    int
	LeafHash []byte
	Path     []ProofNode
}

func (s SampleB) pathLen() int { return len(s.Path) }

// TraceProofB is the Scheme B proof: a root plus K sampled paths.
type TraceProofB struct {
	Root    []byte
	Samples []SampleB
}

func hashState(state []byte) []byte {
	h := sha256.Sum256(state)
	return h[:]
}

// GenerateProofB hashes every state, builds the Merkle tree, and samples k
// distinct leaves (with their paths). rng makes the sampling reproducible.
func GenerateProofB(states [][]byte, k int, rng *mrand.Rand) TraceProofB {
	n := len(states)
	leaves := make([][]byte, n)
	for i, s := range states {
		leaves[i] = hashState(s)
	}
	tree := BuildMerkleTree(leaves)

	if k > n {
		k = n
	}
	idxs := rng.Perm(n)[:k]
	samples := make([]SampleB, k)
	for i, idx := range idxs {
		samples[i] = SampleB{
			Index:    idx,
			LeafHash: leaves[idx],
			Path:     tree.AuthPath(idx),
		}
	}
	return TraceProofB{Root: tree.Root(), Samples: samples}
}

// VerifyProofB checks that every sampled leaf+path recomputes the committed
// root. (In deployment the verifier would also check the revealed leaves
// against an independently known transcript; here we measure the path-check
// cost, which is the dominant verification work.)
func VerifyProofB(p TraceProofB) bool {
	for _, s := range p.Samples {
		if !VerifyAuthPath(s.LeafHash, s.Path, p.Root) {
			return false
		}
	}
	return true
}

// SizeBytes is the on-the-wire proof size: root + per-sample (index + leaf +
// path), where each path node is a 32-byte hash plus a 1-byte direction flag.
func (p TraceProofB) SizeBytes() int {
	size := len(p.Root)
	for _, s := range p.Samples {
		size += 4              // index (uint32)
		size += len(s.LeafHash) // 32
		for _, node := range s.Path {
			size += len(node.Hash) + 1 // hash + direction flag
		}
	}
	return size
}

// ============================================================================
// Scheme C — Full hash-chain commitment (strongest of the three, most costly)
//
// h_0 = H(seed); h_i = H(h_{i-1} || state_i). The final hash commits to the
// entire ordered trace, and producing it requires touching every step.
// PROVES: the complete ordered trace — no sampling, every step is bound in.
// CANNOT PROVE: that the trace is an honest model run (same ceiling as B), and
//           crucially the 32-byte commitment is NOT succinctly verifiable: to
//           check it a verifier must replay the entire N-step chain, which
//           requires the full trace and O(N) work.
// ============================================================================

// HashChainCommit folds every state into a single 32-byte commitment.
func HashChainCommit(states [][]byte, seed []byte) []byte {
	h := sha256.Sum256(seed)
	acc := h[:]
	hasher := sha256.New()
	for _, s := range states {
		hasher.Reset()
		hasher.Write(acc)
		hasher.Write(s)
		acc = hasher.Sum(nil)
	}
	return acc
}

// VerifyHashChain recomputes the chain and compares to the claimed commitment.
// This is O(N) and needs the full trace — that is the whole point of the
// caveat above.
func VerifyHashChain(states [][]byte, seed []byte, commit []byte) bool {
	return bytes.Equal(HashChainCommit(states, seed), commit)
}

// ProofSizeC is the committed value itself.
const ProofSizeC = sha256.Size // 32
