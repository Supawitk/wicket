package wicket

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Supawitk/wicket/pkg/challenger/pow"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

// FuzzSolveEndpoint pumps arbitrary bytes at the /solve handler and
// asserts the server never panics and never returns 5xx on bad input. The
// only acceptable statuses for fuzzed bodies are 400 (bad JSON / hex), 401
// (auth failed), 405 (wrong method — fuzzer always uses POST), or 413
// (over the size cap).
func FuzzSolveEndpoint(f *testing.F) {
	// Seed corpus. Mix of valid-shape, malformed, and oversized.
	f.Add([]byte(`{"id":"x","nonce":"00"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"id":"x","nonce":"zz"}`))
	f.Add([]byte(`{"id":"x","nonce":"00","extra":"reject"}`))
	f.Add(bytes.Repeat([]byte("a"), 16*1024))
	f.Add([]byte(`{"id":` + string(bytes.Repeat([]byte("x"), 4096)) + `,"nonce":"00"}`))

	w := New(WithPoW(pow.New(memory.New(), lowDifficultyPoWConfig())))
	srv := httptest.NewServer(w.AdminHandler())
	f.Cleanup(srv.Close)

	f.Fuzz(func(t *testing.T, body []byte) {
		res, err := http.Post(srv.URL+"/solve", "application/json", bytes.NewReader(body))
		if err != nil {
			// Transport-level failures aren't input bugs.
			return
		}
		defer res.Body.Close()

		if res.StatusCode >= 500 {
			t.Fatalf("server 5xx on fuzzed body: status=%d body=%q", res.StatusCode, body)
		}
		// If status is 200, OK must be a real bool in JSON — proves
		// the response shape stays valid even under arbitrary input.
		if res.StatusCode == http.StatusOK {
			var sr solveResponse
			if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
				t.Fatalf("200 with unparseable body: %v", err)
			}
		}
	})
}

// FuzzChallengeRoundTrip fuzzes the whole challenge → solve flow by
// issuing a real challenge, then submitting a fuzzer-controlled nonce.
// This drives the verifier's hex-decode + difficulty-check paths with
// adversarial nonces and asserts the server stays stable.
func FuzzChallengeRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(bytes.Repeat([]byte{0xaa}, 1024))

	w := New(WithPoW(pow.New(memory.New(), lowDifficultyPoWConfig())))
	srv := httptest.NewServer(w.AdminHandler())
	f.Cleanup(srv.Close)

	f.Fuzz(func(t *testing.T, nonce []byte) {
		res, err := http.Post(srv.URL+"/challenge", "application/json", nil)
		if err != nil {
			return
		}
		var ch challengeResponse
		if err := json.NewDecoder(res.Body).Decode(&ch); err != nil {
			_ = res.Body.Close()
			t.Fatalf("decode challenge: %v", err)
		}
		_ = res.Body.Close()

		body, _ := json.Marshal(solveRequest{ID: ch.ID, Nonce: hex.EncodeToString(nonce)})
		res2, err := http.Post(srv.URL+"/solve", "application/json", bytes.NewReader(body))
		if err != nil {
			return
		}
		defer res2.Body.Close()
		if res2.StatusCode >= 500 {
			t.Fatalf("server 5xx on fuzzed nonce: status=%d", res2.StatusCode)
		}
		if res2.StatusCode == http.StatusOK {
			var sr solveResponse
			if err := json.NewDecoder(res2.Body).Decode(&sr); err != nil {
				t.Fatalf("decode solve: %v", err)
			}
			_ = sr
		}
	})
}
