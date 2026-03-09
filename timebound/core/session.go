package core

import "sync"

// SessionStore provides thread-safe in-memory storage for active sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates a new empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Add stores a session in the store.
func (s *SessionStore) Add(session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

// Get retrieves a session by ID. Returns nil if not found.
func (s *SessionStore) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// ListActive returns all non-expired sessions.
func (s *SessionStore) ListActive() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*Session
	for _, session := range s.sessions {
		if !session.IsExpired() {
			active = append(active, session)
		}
	}
	return active
}

// PurgeExpired removes all expired sessions from the store and returns them.
func (s *SessionStore) PurgeExpired() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []*Session
	for id, session := range s.sessions {
		if session.IsExpired() {
			expired = append(expired, session)
			delete(s.sessions, id)
		}
	}
	return expired
}
