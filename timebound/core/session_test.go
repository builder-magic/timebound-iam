package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSessionIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{ExpiresAt: tt.expiresAt}
			if got := s.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionProfileSerialization(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		wantInJSON bool
	}{
		{
			name:       "with profile",
			profile:    "prod",
			wantInJSON: true,
		},
		{
			name:       "empty profile omitted",
			profile:    "",
			wantInJSON: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				ID:        "test-1",
				Provider:  ProviderAWS,
				Services:  []string{"s3"},
				Level:     LevelReadOnly,
				Profile:   tt.profile,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}

			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			_, exists := m["profile"]
			if exists != tt.wantInJSON {
				t.Errorf("profile in JSON = %v, want %v (json: %s)", exists, tt.wantInJSON, string(data))
			}

			if tt.wantInJSON {
				if m["profile"] != tt.profile {
					t.Errorf("profile = %v, want %q", m["profile"], tt.profile)
				}
			}

			// Round-trip: unmarshal back to Session
			var roundTrip Session
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("round-trip unmarshal: %v", err)
			}
			if roundTrip.Profile != tt.profile {
				t.Errorf("round-trip profile = %q, want %q", roundTrip.Profile, tt.profile)
			}
		})
	}
}

func TestSessionStoreAdd(t *testing.T) {
	store := NewSessionStore()
	session := &Session{
		ID:        "test-1",
		Services:  []string{"s3"},
		Level:     LevelReadOnly,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	store.Add(session)
	got := store.Get("test-1")
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.ID != session.ID {
		t.Errorf("got ID %q, want %q", got.ID, session.ID)
	}
}

func TestSessionStoreGetNotFound(t *testing.T) {
	store := NewSessionStore()
	got := store.Get("nonexistent")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestSessionStoreListActive(t *testing.T) {
	store := NewSessionStore()

	store.Add(&Session{
		ID:        "active-1",
		Services:  []string{"s3"},
		Level:     LevelReadOnly,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	store.Add(&Session{
		ID:        "active-2",
		Services:  []string{"ec2"},
		Level:     LevelFull,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	})
	store.Add(&Session{
		ID:        "expired-1",
		Services:  []string{"lambda"},
		Level:     LevelReadOnly,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	active := store.ListActive()
	if len(active) != 2 {
		t.Errorf("expected 2 active sessions, got %d", len(active))
	}

	ids := make(map[string]bool)
	for _, s := range active {
		ids[s.ID] = true
	}
	if !ids["active-1"] || !ids["active-2"] {
		t.Error("expected active-1 and active-2 in active sessions")
	}
	if ids["expired-1"] {
		t.Error("expired session should not be in active list")
	}
}

func TestSessionStorePurgeExpired(t *testing.T) {
	store := NewSessionStore()

	store.Add(&Session{
		ID:        "active-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	store.Add(&Session{
		ID:        "expired-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	store.Add(&Session{
		ID:        "expired-2",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})

	purged := store.PurgeExpired()
	if len(purged) != 2 {
		t.Errorf("expected 2 purged sessions, got %d", len(purged))
	}

	// Active session should still be accessible
	if store.Get("active-1") == nil {
		t.Error("active-1 should still be in store")
	}

	// Expired sessions should be gone
	if store.Get("expired-1") != nil {
		t.Error("expired-1 should have been purged")
	}
	if store.Get("expired-2") != nil {
		t.Error("expired-2 should have been purged")
	}
}
