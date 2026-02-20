package cli

import (
	"testing"

	timebound "github.com/builder-magic/timebound-iam/timebound/aws"
)

func TestScopeFlagSet(t *testing.T) {
	tests := []struct {
		name    string
		inputs  []string
		want    []timebound.ServiceScope
		wantErr bool
	}{
		{
			name:   "single scope",
			inputs: []string{"s3:ro"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
			},
		},
		{
			name:   "comma-separated scopes",
			inputs: []string{"s3:ro,dynamodb:full"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
				{Service: "dynamodb", Level: timebound.LevelFull},
			},
		},
		{
			name:   "repeated flag calls",
			inputs: []string{"s3:ro", "lambda:full"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
				{Service: "lambda", Level: timebound.LevelFull},
			},
		},
		{
			name:   "read_only alias",
			inputs: []string{"s3:read_only"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
			},
		},
		{
			name:   "readonly alias",
			inputs: []string{"s3:readonly"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
			},
		},
		{
			name:   "uppercase normalized",
			inputs: []string{"S3:RO"},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
			},
		},
		{
			name:    "missing colon",
			inputs:  []string{"s3ro"},
			wantErr: true,
		},
		{
			name:    "empty service",
			inputs:  []string{":ro"},
			wantErr: true,
		},
		{
			name:    "empty level",
			inputs:  []string{"s3:"},
			wantErr: true,
		},
		{
			name:    "unknown level",
			inputs:  []string{"s3:admin"},
			wantErr: true,
		},
		{
			name:   "whitespace trimmed",
			inputs: []string{" s3 : ro , dynamodb : full "},
			want: []timebound.ServiceScope{
				{Service: "s3", Level: timebound.LevelReadOnly},
				{Service: "dynamodb", Level: timebound.LevelFull},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f scopeFlag
			var err error
			for _, input := range tt.inputs {
				if setErr := f.Set(input); setErr != nil {
					err = setErr
					break
				}
			}

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(f.scopes) != len(tt.want) {
				t.Fatalf("got %d scopes, want %d", len(f.scopes), len(tt.want))
			}
			for i, got := range f.scopes {
				if got.Service != tt.want[i].Service {
					t.Errorf("scope[%d].Service = %q, want %q", i, got.Service, tt.want[i].Service)
				}
				if got.Level != tt.want[i].Level {
					t.Errorf("scope[%d].Level = %q, want %q", i, got.Level, tt.want[i].Level)
				}
			}
		})
	}
}

func TestScopeFlagString(t *testing.T) {
	f := &scopeFlag{
		scopes: []timebound.ServiceScope{
			{Service: "s3", Level: timebound.LevelReadOnly},
			{Service: "dynamodb", Level: timebound.LevelFull},
		},
	}
	got := f.String()
	want := "s3:read_only,dynamodb:full"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
