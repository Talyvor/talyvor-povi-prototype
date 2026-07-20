// Command report runs each proof scheme through testing.Benchmark and prints a
// consolidated markdown table of gen_time / proof_bytes / verify_time. The
// numbers it prints are the source of truth for RESULTS.md.
//
//	go run ./cmd/report
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"

	povi "povi-prototype"
)

const stateBytes = 256

var Ns = []int{100, 1000, 10000}
var Ks = []int{1, 4, 16, 32}

// genStates builds n synthetic execution-step states; only their size affects
// the cost we measure.
func genStates(n, size int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		s := make([]byte, size)
		for j := range s {
			s[j] = byte((i*131 + j*7) & 0xff)
		}
		out[i] = s
	}
	return out
}

func dur(nsPerOp float64) string {
	switch {
	case nsPerOp < 1000:
		return fmt.Sprintf("%.0f ns", nsPerOp)
	case nsPerOp < 1e6:
		return fmt.Sprintf("%.2f µs", nsPerOp/1e3)
	default:
		return fmt.Sprintf("%.3f ms", nsPerOp/1e6)
	}
}

func bytesStr(b int) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.1f KB", float64(b)/1024)
}

type row struct {
	scheme, n, k, gen, proof, verify string
}

func main() {
	var rows []row

	// ---- Scheme A ----
	{
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		pub := priv.Public().(ed25519.PublicKey)
		r := povi.Receipt{
			RequestID: "req", PromptHash: hash32(1), ResponseHash: hash32(2),
			Model: "talyvor-llm-7b", TokenCount: 1234, Timestamp: 1764460800,
		}
		var sig []byte
		gen := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sig = povi.SignReceipt(priv, r)
			}
		})
		ver := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = povi.VerifyReceipt(pub, r, sig)
			}
		})
		rows = append(rows, row{"A signed-receipt", "—", "—",
			dur(float64(gen.NsPerOp())), bytesStr(povi.ProofSizeA), dur(float64(ver.NsPerOp()))})
	}

	// ---- Scheme B ----
	for _, n := range Ns {
		states := genStates(n, stateBytes)
		for _, k := range Ks {
			rng := mrand.New(mrand.NewSource(1))
			proof := povi.GenerateProofB(states, k, rng)
			size := proof.SizeBytes()
			gen := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = povi.GenerateProofB(states, k, rng)
				}
			})
			ver := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = povi.VerifyProofB(proof)
				}
			})
			rows = append(rows, row{"B merkle-trace", itoa(n), itoa(k),
				dur(float64(gen.NsPerOp())), bytesStr(size), dur(float64(ver.NsPerOp()))})
		}
	}

	// ---- Scheme C ----
	seed := []byte("genesis")
	for _, n := range Ns {
		states := genStates(n, stateBytes)
		commit := povi.HashChainCommit(states, seed)
		gen := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = povi.HashChainCommit(states, seed)
			}
		})
		ver := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = povi.VerifyHashChain(states, seed, commit)
			}
		})
		// proof_bytes is the 32-byte commitment, but verification needs the
		// FULL trace; we note the trace size separately in RESULTS.md.
		rows = append(rows, row{"C hash-chain", itoa(n), "—",
			dur(float64(gen.NsPerOp())), bytesStr(povi.ProofSizeC), dur(float64(ver.NsPerOp())) + " *"})
	}

	fmt.Println("| Scheme | N | K | gen_time | proof_bytes | verify_time |")
	fmt.Println("|--------|---|---|----------|-------------|-------------|")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n", r.scheme, r.n, r.k, r.gen, r.proof, r.verify)
	}
	fmt.Println()
	fmt.Println("`*` Scheme C verify replays the entire N-step chain and therefore")
	fmt.Println("    requires the full trace (≈ N × state_bytes); the 32-byte commitment")
	fmt.Println("    is NOT independently verifiable on its own.")
}

func hash32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
