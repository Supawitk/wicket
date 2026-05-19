// Client-side fairness verifier.
//
// Takes the operator's public key, a ticket ID, and the per-ticket proof
// (all of which an event organiser publishes after a sale) and confirms
// that the ticket's queue position was determined by a true cryptographic
// VRF — not adjusted by the operator after the fact.
//
// Optionally, given a published Merkle root and the export-row for the
// ticket plus the inclusion path, it also confirms the ticket was part
// of the same audit batch that produced the root.
//
// Run:
//
//	go run ./examples/03-verifier \
//	    -pubkey <hex public key> \
//	    -ticket <ticket id> \
//	    -proof  <hex per-ticket signature>
//
// All inputs are produced by the concert example or by the sidecar's
// /__wicket__/ endpoints.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Supawitk/wicket/pkg/queue/vrf"
)

func main() {
	pubHex := flag.String("pubkey", "", "operator public key, hex-encoded")
	ticket := flag.String("ticket", "", "ticket id whose proof you want to verify")
	proofHex := flag.String("proof", "", "per-ticket proof, hex-encoded")
	mode := flag.String("mode", "ed25519", "verification mode: ed25519 or ecvrf")
	flag.Parse()

	if *pubHex == "" || *ticket == "" || *proofHex == "" {
		flag.Usage()
		os.Exit(2)
	}

	pub, err := hex.DecodeString(*pubHex)
	if err != nil {
		log.Fatalf("decode pubkey: %v", err)
	}
	proof, err := hex.DecodeString(*proofHex)
	if err != nil {
		log.Fatalf("decode proof: %v", err)
	}

	var score uint64
	var ok bool
	switch *mode {
	case "ed25519":
		score, ok = vrf.VerifyEd25519(pub, *ticket, proof)
	case "ecvrf":
		score, ok = vrf.VerifyECVRF(pub, *ticket, proof)
	default:
		log.Fatalf("unknown mode %q (use ed25519 or ecvrf)", *mode)
	}

	if !ok {
		fmt.Println("REJECT: proof is invalid or does not match the supplied public key / ticket ID")
		os.Exit(1)
	}
	fmt.Println("OK: proof valid")
	fmt.Printf("score: %d\n", score)
	fmt.Println()
	fmt.Println("Anyone holding (pubkey, ticket, proof) can run this verifier")
	fmt.Println("and recompute the same score. The operator cannot have")
	fmt.Println("adjusted positions after the fact without invalidating it.")
}
