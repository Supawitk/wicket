package wicket

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/metrics"
)

// maxAdminBodyBytes caps request bodies on admin endpoints. None of the
// JSON payloads ever exceed a few hundred bytes; capping rejects oversized
// requests before they consume memory.
const maxAdminBodyBytes = 8 * 1024

// AdminHandler returns an HTTP handler that exposes JSON endpoints for the
// configured challenger and queue components. Mount it under a path of
// your choice (the README and examples use /__wicket__/).
//
// Endpoints (all relative to the mount point):
//
//	POST  /challenge          issue a new bot challenge
//	POST  /solve              verify a challenge solution
//	POST  /enqueue            join the admission queue
//	GET   /status?ticket=ID   queue status for a ticket
//
// All responses are JSON. Errors take the shape {"error":"..."} with the
// matching HTTP status. Endpoints not backed by configured components
// return 404.
func (w *Wicket) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", w.handleChallenge)
	mux.HandleFunc("/solve", w.handleSolve)
	mux.HandleFunc("/enqueue", w.handleEnqueue)
	mux.HandleFunc("/status", w.handleStatus)
	return mux
}

type challengeResponse struct {
	ID         string `json:"id"`
	Payload    string `json:"payload"`
	Difficulty int    `json:"difficulty"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (w *Wicket) handleChallenge(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if w.challenger == nil {
		writeError(rw, http.StatusNotFound, "challenger not configured")
		return
	}
	ch, err := w.challenger.Issue(r.Context(), challenger.Hint{})
	if err != nil {
		writeError(rw, http.StatusInternalServerError, "issue failed")
		return
	}
	if w.metrics != nil {
		w.metrics.ChallengeIssued.Inc()
	}
	writeJSON(rw, http.StatusOK, challengeResponse{
		ID:         ch.ID,
		Payload:    hex.EncodeToString(ch.Payload),
		Difficulty: ch.Difficulty,
		ExpiresAt:  ch.ExpiresAt.Unix(),
	})
}

type solveRequest struct {
	ID    string `json:"id"`
	Nonce string `json:"nonce"`
}

type solveResponse struct {
	OK    bool   `json:"ok"`
	Token string `json:"token,omitempty"`
}

func (w *Wicket) handleSolve(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if w.challenger == nil {
		writeError(rw, http.StatusNotFound, "challenger not configured")
		return
	}
	var req solveRequest
	if err := decodeJSON(rw, r, &req); err != nil {
		writeError(rw, http.StatusBadRequest, "bad request")
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "bad nonce")
		return
	}
	if err := w.challenger.Verify(r.Context(), challenger.Solution{ID: req.ID, Nonce: nonce}); err != nil {
		if w.metrics != nil {
			label := metrics.ChallengeInvalid
			if err == challenger.ErrUnknownID {
				label = metrics.ChallengeUnknown
			}
			w.metrics.ChallengeVerified.WithLabelValues(label).Inc()
		}
		writeJSON(rw, http.StatusUnauthorized, solveResponse{OK: false})
		return
	}
	if w.metrics != nil {
		w.metrics.ChallengeVerified.WithLabelValues(metrics.ChallengeOK).Inc()
	}
	resp := solveResponse{OK: true}
	if w.issuer != nil {
		token, err := w.issuer.Issue("pow:" + req.ID)
		if err == nil {
			resp.Token = token
		}
	}
	writeJSON(rw, http.StatusOK, resp)
}

type enqueueResponse struct {
	TicketID string `json:"ticket_id"`
	Issued   int64  `json:"issued"`
}

func (w *Wicket) handleEnqueue(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if w.queue == nil {
		writeError(rw, http.StatusNotFound, "queue not configured")
		return
	}
	// Drain at most maxAdminBodyBytes so a client that posts a giant body
	// cannot exhaust memory. /enqueue ignores the body content entirely
	// but a misbehaving client might still send one.
	r.Body = http.MaxBytesReader(rw, r.Body, maxAdminBodyBytes)
	tk, err := w.queue.Enqueue(r.Context(), w.keyFn(r))
	if err != nil {
		writeError(rw, http.StatusInternalServerError, "enqueue failed")
		return
	}
	if w.metrics != nil {
		if n, err := w.queue.Size(r.Context()); err == nil {
			w.metrics.QueueSize.Set(float64(n))
		}
	}
	writeJSON(rw, http.StatusOK, enqueueResponse{
		TicketID: tk.ID,
		Issued:   tk.Issued.Unix(),
	})
}

type statusResponse struct {
	TicketID string `json:"ticket_id"`
	Position int64  `json:"position"`
	Cursor   int64  `json:"cursor"`
	Ahead    int64  `json:"ahead"`
	Admitted bool   `json:"admitted"`
}

func (w *Wicket) handleStatus(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(rw, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if w.queue == nil {
		writeError(rw, http.StatusNotFound, "queue not configured")
		return
	}
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		writeError(rw, http.StatusBadRequest, "ticket required")
		return
	}
	s, err := w.queue.Status(r.Context(), ticket)
	if err != nil {
		writeError(rw, http.StatusNotFound, "unknown ticket")
		return
	}
	if w.metrics != nil {
		w.metrics.QueueCursor.Set(float64(s.Cursor))
	}
	writeJSON(rw, http.StatusOK, statusResponse{
		TicketID: s.TicketID,
		Position: s.Position,
		Cursor:   s.Cursor,
		Ahead:    s.Ahead,
		Admitted: s.Admitted,
	})
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(rw http.ResponseWriter, status int, msg string) {
	writeJSON(rw, status, errorResponse{Error: msg})
}

func writeJSON(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}

// decodeJSON enforces a body size cap and disallows unknown fields. Returns
// the underlying decode error so callers can translate to a status code.
func decodeJSON(rw http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(rw, r.Body, maxAdminBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
