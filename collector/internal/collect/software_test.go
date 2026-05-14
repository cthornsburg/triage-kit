package collect

import "testing"

func TestInstallDateStatus(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "missing", in: "", want: "missing"},
		{name: "compact yyyymmdd", in: "20260513", want: "present_yyyymmdd_unverified"},
		{name: "other format", in: "5/13/2026", want: "present_unreliable_format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := installDateStatus(tt.in); got != tt.want {
				t.Fatalf("installDateStatus(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
