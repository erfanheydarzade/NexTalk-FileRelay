package client

import "testing"

// joinURL mirrors the identical helper in transports/filerelay/bridge (see
// that package's comment for why it exists): ShardURL/RouterURL are
// caller-supplied and may carry a trailing slash, and naive "+"
// concatenation with a route path then produces a double slash that
// several HTTP routers treat as a distinct, unmatched path — surfacing as
// a 404 instead of reaching the intended handler.
func TestJoinURL(t *testing.T) {
	cases := []struct {
		name  string
		base  string
		route string
		want  string
	}{
		{"no trailing slash", "https://shard.example.com", "/fr/v1/send", "https://shard.example.com/fr/v1/send"},
		{"trailing slash on base", "https://shard.example.com/", "/fr/v1/send", "https://shard.example.com/fr/v1/send"},
		{"multiple trailing slashes", "https://shard.example.com///", "/fr/v1/send", "https://shard.example.com/fr/v1/send"},
		{"route missing leading slash", "https://shard.example.com", "fr/v1/send", "https://shard.example.com/fr/v1/send"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := joinURL(tc.base, tc.route)
			if got != tc.want {
				t.Errorf("joinURL(%q, %q) = %q, want %q", tc.base, tc.route, got, tc.want)
			}
		})
	}
}
