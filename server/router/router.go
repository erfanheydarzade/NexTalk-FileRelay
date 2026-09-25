// Package router derives opaque mailbox IDs, publishes the signed routing
// table, and resolves mailboxes to shards. It never proxies message bodies.
package router

// Table is the legacy in-memory routing table view (wire form is
// protocol.RoutingTable, schema 56). Kept for existing callers.
type Table struct {
	Version           uint32
	GeneratedAt       uint64
	ExpiresAt         uint64
	Algorithm         string // "filerelay-sha256-modn-v1"
	ShardURLs         []string
	ReplicationFactor uint32
	PriorShardCounts  []uint32
	RouterPub         [32]byte
	Signature         [64]byte // over protocol.DomainRoutingTable canonical
}
