package povi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	mrand "math/rand"
	"testing"
)

// makeStates returns n distinct "execution-step states" of stateSize bytes each.
func makeStates(n, stateSize int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		s := make([]byte, stateSize)
		// deterministic but step-dependent content
		for j := range s {
			s[j] = byte((i*131 + j*7) & 0xff)
		}
		out[i] = s
	}
	return out
}

// ---- Scheme A: Signed Receipt ----

func TestSchemeAValidReceiptVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleReceipt()
	sig := SignReceipt(priv, r)
	if !VerifyReceipt(pub, r, sig) {
		t.Fatal("valid receipt failed verification")
	}
}

func TestSchemeATamperedReceiptFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleReceipt()
	sig := SignReceipt(priv, r)

	r.TokenCount += 1 // tamper a single field
	if VerifyReceipt(pub, r, sig) {
		t.Fatal("tampered receipt incorrectly verified")
	}
}

func TestSchemeAWrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleReceipt()
	sig := SignReceipt(priv, r)
	if VerifyReceipt(otherPub, r, sig) {
		t.Fatal("receipt verified under the wrong public key")
	}
}

func sampleReceipt() Receipt {
	ph := sha256.Sum256([]byte("the prompt"))
	rh := sha256.Sum256([]byte("the response"))
	return Receipt{
		RequestID:    "req-12345",
		PromptHash:   ph[:],
		ResponseHash: rh[:],
		Model:        "talyvor-llm-7b",
		TokenCount:   1234,
		Timestamp:    1764460800,
	}
}

// ---- Scheme B: Merkle-committed execution trace ----

func TestSchemeBHonestProofVerifies(t *testing.T) {
	states := makeStates(1000, 256)
	rng := mrand.New(mrand.NewSource(1))
	proof := GenerateProofB(states, 16, rng)
	if !VerifyProofB(proof) {
		t.Fatal("honest Scheme B proof failed verification")
	}
	if len(proof.Samples) != 16 {
		t.Fatalf("expected 16 samples, got %d", len(proof.Samples))
	}
}

func TestSchemeBTamperedSampleFails(t *testing.T) {
	states := makeStates(1000, 256)
	rng := mrand.New(mrand.NewSource(2))
	proof := GenerateProofB(states, 16, rng)

	// Corrupt one revealed leaf; its path can no longer recompute the root.
	bad := sha256.Sum256([]byte("not the real state"))
	proof.Samples[0].LeafHash = bad[:]
	if VerifyProofB(proof) {
		t.Fatal("Scheme B verified despite a tampered sampled leaf")
	}
}

func TestSchemeBSizeMatchesFormula(t *testing.T) {
	states := makeStates(1000, 256)
	rng := mrand.New(mrand.NewSource(3))
	k := 4
	proof := GenerateProofB(states, k, rng)
	depth := proof.Samples[0].pathLen()
	want := 32 + k*(4+32+depth*(32+1))
	if got := proof.SizeBytes(); got != want {
		t.Fatalf("SizeBytes=%d, formula=%d (depth=%d)", got, want, depth)
	}
}

// ---- Scheme C: full hash chain ----

func TestSchemeCHonestChainVerifies(t *testing.T) {
	states := makeStates(1000, 256)
	seed := []byte("genesis")
	commit := HashChainCommit(states, seed)
	if !VerifyHashChain(states, seed, commit) {
		t.Fatal("honest hash chain failed verification")
	}
	if len(commit) != 32 {
		t.Fatalf("commit should be 32 bytes, got %d", len(commit))
	}
}

func TestSchemeCTamperedStepFails(t *testing.T) {
	states := makeStates(1000, 256)
	seed := []byte("genesis")
	commit := HashChainCommit(states, seed)

	states[500][0] ^= 0xff // flip one bit in one step
	if VerifyHashChain(states, seed, commit) {
		t.Fatal("hash chain verified despite a tampered step")
	}
}
