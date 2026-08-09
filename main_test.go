package main

import "testing"

func TestValidateCacheSeconds(t *testing.T) {
	if defaultCacheSeconds != 3 {
		t.Fatalf("default cache = %d seconds, want 3", defaultCacheSeconds)
	}

	tests := []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{name: "below minimum", seconds: -1, wantErr: true},
		{name: "disabled", seconds: 0},
		{name: "default", seconds: 3},
		{name: "maximum", seconds: 60},
		{name: "above maximum", seconds: 61, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCacheSeconds(test.seconds)
			if (err != nil) != test.wantErr {
				t.Errorf("validateCacheSeconds(%d) error = %v, wantErr %t", test.seconds, err, test.wantErr)
			}
		})
	}
}
