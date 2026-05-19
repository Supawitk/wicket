package wicket

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/metrics"
)

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
//	GET   /commitment         queue's seed commitment (VRF queue only)
//
// Endpoints not backed by configured components return 404.
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
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if w.challenger == nil {
		http.Error(rw, "challenger not configured", http.StatusNotFound)
		return
	}
	ch, err := w.challenger.Issue(r.Context(), challenger.Hint{})
	if err != nil {
		http.Error(rw, "issue failed", http.StatusInternalServerError)
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
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if w.challenger == nil {
		http.Error(rw, "challenger not configured", http.StatusNotFound)
		return
	}
	var req solveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		http.Error(rw, "bad nonce", http.StatusBadRequest)
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
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if w.queue == nil {
		http.Error(rw, "queue not configured", http.StatusNotFound)
		return
	}
	tk, err := w.queue.Enqueue(r.Context(), w.keyFn(r))
	if err != nil {
		http.Error(rw, "enqueue failed", http.StatusInternalServerError)
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
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if w.queue == nil {
		http.Error(rw, "queue not configured", http.StatusNotFound)
		return
	}
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		http.Error(rw, "ticket required", http.StatusBadRequest)
		return
	}
	s, err := w.queue.Status(r.Context(), ticket)
	if err != nil {
		http.Error(rw, "unknown ticket", http.StatusNotFound)
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

func writeJSON(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}
