// Package admission issues and verifies short-lived, single-use admission
// tokens. A token is an HMAC-SHA256-signed envelope containing a random
// nonce, an expiry, and an opaque caller-supplied subject (e.g. a queue
// ticket ID or an identity nullifier). The Verifier rejects expired tokens
// and rejects re-use by consuming the nonce in a store.Store.
//
// Wicket uses this to give callers a one-shot proof that "Wicket admitted
// this request" — the protected backend can require an X-Wicket-Token
// header on every protected endpoint without re-running the full admission
// pipeline per request.
package admission

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Supawitk/wicket/pkg/store"
)

var (
	ErrMalformed = errors.New("admission: malformed token")
	ErrSignature = errors.New("admission: bad signature")
	ErrExpired   = errors.New("admission: token expired")
	ErrReplayed  = errors.New("admission: token already consumed")
)

type Config struct {
	Secret []byte
	TTL    time.Duration
	Now    func() time.Time
}

type Issuer struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewIssuer(cfg Config) (*Issuer, error) {
	if len(cfg.Secret) < 16 {
		return nil, errors.New("admission: secret must be >= 16 bytes")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Issuer{
		secret: append([]byte(nil), cfg.Secret...),
		ttl:    ttl,
		now:    now,
	}, nil
}

// Issue mints a new admission token. The subject is opaque to the package;
// callers typically use a queue ticket ID, an identity nullifier hash, or
// a tuple of those joined with ":".
func (i *Issuer) Issue(subject string) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("admission: nonce: %w", err)
	}
	exp := i.now().Add(i.ttl).Unix()
	payload := fmt.Sprintf("%s.%d.%s",
		base64.RawURLEncoding.EncodeToString(nonce),
		exp,
		base64.RawURLEncoding.EncodeToString([]byte(subject)),
	)
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

type Verifier struct {
	secret []byte
	now    func() time.Time
	store  store.Store
}

// NewVerifier validates tokens issued by an Issuer with the same secret.
// The store is used to record consumed nonces so a captured token cannot
// be replayed within its TTL.
func NewVerifier(secret []byte, nonceStore store.Store, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		secret: append([]byte(nil), secret...),
		now:    now,
		store:  nonceStore,
	}
}

// Verify checks the signature, expiry, and replay status of token. On
// success it returns the subject the token was issued for and consumes
// the nonce. Subsequent verifications of the same token return ErrReplayed.
func (v *Verifier) Verify(ctx context.Context, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", ErrMalformed
	}
	payload := strings.Join(parts[:3], ".")
	sigGiven, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", ErrMalformed
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(payload))
	sigWant := mac.Sum(nil)
	if !hmac.Equal(sigGiven, sigWant) {
		return "", ErrSignature
	}

	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrMalformed
	}
	if v.now().Unix() >= exp {
		return "", ErrExpired
	}
	subj, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrMalformed
	}

	// Consume the nonce: SetNX guarantees one-shot semantics. TTL slightly
	// past the expiry so a clock skew can't permit a replay just before
	// the original expiry.
	ttl := time.Until(time.Unix(exp, 0)) + time.Minute
	if err := v.store.SetNX(ctx, nonceKey(parts[0]), []byte{1}, ttl); err != nil {
		if errors.Is(err, store.ErrExists) {
			return "", ErrReplayed
		}
		return "", fmt.Errorf("admission: consume nonce: %w", err)
	}

	return string(subj), nil
}

func nonceKey(nonceB64 string) string { return "adm:nonce:" + nonceB64 }
