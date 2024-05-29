package inmemory

import (
	"context"
	"sync"
)

// Nonce tracks seen nonces in memory.
//
// It is not recommended to use this in production because
// this will not persist across restarts.
type Nonce struct {
	mu     sync.Mutex
	nonces map[string]bool
}

func NewNonceStorage() *Nonce {
	return &Nonce{
		nonces: map[string]bool{},
	}
}

func (m *Nonce) Seen(ctx context.Context, nonce string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, seen := m.nonces[nonce]
	if seen {
		return true, nil
	}

	m.nonces[nonce] = true
	return false, nil
}
