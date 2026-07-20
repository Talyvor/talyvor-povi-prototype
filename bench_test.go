package povi

import (
	"crypto/ed25519"
	"crypto/rand"
	mrand "math/rand"
	"testing"
)

// stateBytes is the assumed size of one execution-step's intermediate state
// that gets hashed. 256 bytes models e.g. a token id plus a compact logit /
// hidden-state summary. Cost scales linearly with this for Schemes B and C, so
// it is called out explicitly in RESULTS.md.
const stateBytes = 256

var benchN = []int{100, 1000, 10000}
var benchK = []int{1, 4, 16, 32}

// ---- Scheme A ----

func BenchmarkSchemeA_Gen(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleReceipt()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SignReceipt(priv, r)
	}
	b.ReportMetric(float64(ProofSizeA), "proof_bytes")
}

func BenchmarkSchemeA_Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleReceipt()
	sig := SignReceipt(priv, r)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyReceipt(pub, r, sig)
	}
}

// ---- Scheme B ----

func BenchmarkSchemeB_Gen(b *testing.B) {
	for _, n := range benchN {
		states := makeStates(n, stateBytes)
		for _, k := range benchK {
			b.Run(name(n, k), func(b *testing.B) {
				rng := mrand.New(mrand.NewSource(1))
				b.ReportAllocs()
				b.ResetTimer()
				var sz int
				for i := 0; i < b.N; i++ {
					p := GenerateProofB(states, k, rng)
					sz = p.SizeBytes()
				}
				b.StopTimer()
				b.ReportMetric(float64(sz), "proof_bytes")
			})
		}
	}
}

func BenchmarkSchemeB_Verify(b *testing.B) {
	for _, n := range benchN {
		states := makeStates(n, stateBytes)
		for _, k := range benchK {
			b.Run(name(n, k), func(b *testing.B) {
				rng := mrand.New(mrand.NewSource(1))
				p := GenerateProofB(states, k, rng)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !VerifyProofB(p) {
						b.Fatal("verify failed")
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(p.SizeBytes()), "proof_bytes")
			})
		}
	}
}

// ---- Scheme C ----

func BenchmarkSchemeC_Gen(b *testing.B) {
	seed := []byte("genesis")
	for _, n := range benchN {
		states := makeStates(n, stateBytes)
		b.Run(nameN(n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = HashChainCommit(states, seed)
			}
			b.ReportMetric(float64(ProofSizeC), "proof_bytes")
		})
	}
}

func BenchmarkSchemeC_Verify(b *testing.B) {
	seed := []byte("genesis")
	for _, n := range benchN {
		states := makeStates(n, stateBytes)
		commit := HashChainCommit(states, seed)
		b.Run(nameN(n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !VerifyHashChain(states, seed, commit) {
					b.Fatal("verify failed")
				}
			}
			b.ReportMetric(float64(ProofSizeC), "proof_bytes")
		})
	}
}

func name(n, k int) string  { return "N=" + itoa(n) + "/K=" + itoa(k) }
func nameN(n int) string    { return "N=" + itoa(n) }
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
