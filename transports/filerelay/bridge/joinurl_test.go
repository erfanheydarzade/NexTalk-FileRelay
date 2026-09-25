package main

import "testing"

// joinURL must never let a trailing slash on a caller-supplied base URL
// produce a double slash before the route: that turns into a distinct,
// unregistered path on servers like Cloudflare Workers and comes back as
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
		{"base with path prefix and trailing slash", "https://gw.example.com/relay/", "/fr/v1/hello", "https://gw.example.com/relay/fr/v1/hello"},
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
