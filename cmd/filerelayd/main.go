// Command filerelayd runs a single-binary FileRelay deployment: router +
// shard sharing one in-memory store. For demos, LAN relays, and the NexTalk
// courier-bridge real scenario — not for multi-shard production (deploy the
// shard/router handlers separately with shared KV there).
//
// Usage:
//
//	filerelayd --addr 127.0.0.1:8080 [--server-secret <64-hex>]
//	filerelayd --addr 127.0.0.1:8080 --print-template
//	filerelayd --version
//
// Without --server-secret a fresh secret is generated and printed (save it:
// rotating it orphans every mailbox). Router signing keys are generated
// ephemerally at boot and published in the routing table.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/erfanheydarzade/NexTalk-FileRelay/internal/buildinfo"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/router"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/shard"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/storage"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	secretHex := flag.String("server-secret", "", "SERVER_SECRET as 64 hex chars (generated if empty)")
	printTemplate := flag.Bool("print-template", false, "print a client config template and exit")
	printVersion := flag.Bool("version", false, "print version, commit, and build date, then exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("filerelayd %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return
	}

	var secret []byte
	if *secretHex == "" {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			fmt.Fprintln(os.Stderr, "rand:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "generated SERVER_SECRET (save it!): %x\n", secret)
	} else {
		var err error
		secret, err = hex.DecodeString(*secretHex)
		if err != nil || len(secret) != 32 {
			fmt.Fprintln(os.Stderr, "server-secret must be 64 hex chars")
			os.Exit(2)
		}
	}

	rpub, rpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	var rpubArr [32]byte
	copy(rpubArr[:], rpub)

	store := storage.NewMemStore()
	baseURL := "http://" + *addr
	routerH := router.NewHandler(router.Config{
		Secret:     secret,
		Shards:     []router.ShardRef{{URL: baseURL, Store: store}},
		Version:    1,
		RouterPub:  rpubArr,
		RouterPriv: rpriv,
	})
	shardH := shard.NewHandler(store, nil, shard.DefaultRateLimits())

	mux := http.NewServeMux()
	mux.Handle("/fr/v1/register", routerH)
	mux.Handle("/fr/v1/resolve", routerH)
	mux.Handle("/fr/v1/table", routerH)
	mux.Handle("/fr/v1/hello", routerH) // router answers hello; shard hello shares the path
	mux.Handle("/fr/v1/send", shardH)
	mux.Handle("/fr/v1/receive", shardH)
	mux.Handle("/fr/v1/ack", shardH)
	mux.Handle("/fr/v1/xfer/", shardH)

	if *printTemplate {
		fmt.Printf("ROUTER_URL=%s\nSHARD_URL=%s\n", baseURL, baseURL)
		return
	}
	fmt.Fprintf(os.Stderr, "filerelayd on %s (router+shard, replication=1)\n", baseURL)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
