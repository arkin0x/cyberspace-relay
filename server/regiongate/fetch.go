package regiongate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0ceanslim/grain/client/core"
	"github.com/0ceanslim/grain/client/core/tools"
	nostr "github.com/0ceanslim/grain/server/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
)

// RelaySource fetches movement events from other relays. It answers NIP-42
// AUTH challenges with its own key, because the main Cyberspace relay
// (wss://cyberspace.nostr1.com) refuses reads without AUTH. Any key works
// there; a fresh one is generated at startup unless one is configured.
type RelaySource struct {
	Relays  []string
	Timeout time.Duration
	AuthKey *btcec.PrivateKey
}

// Movement implements Source: every relay is queried concurrently and the
// results merged. It fails only when every relay fails. A relay that fails
// outright is left out; one that is capped or fails part way makes the
// answer Capped or Partial.
func (s RelaySource) Movement(ctx context.Context, pubkey string, q ChainQuery) ([]nostr.Event, Coverage, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	type result struct {
		evs []nostr.Event
		cov Coverage
		err error
	}
	results := make(chan result, len(s.Relays))
	for _, url := range s.Relays {
		go func(url string) {
			evs, cov, err := s.fetch(ctx, url, pubkey, q)
			if err != nil {
				err = fmt.Errorf("%s: %w", url, err)
			}
			results <- result{evs, cov, err}
		}(url)
	}
	var out []nostr.Event
	var cov Coverage
	var errs []string
	for range s.Relays {
		r := <-results
		if r.err != nil {
			errs = append(errs, r.err.Error())
			continue
		}
		cov.add(r.cov)
		out = append(out, r.evs...)
	}
	if len(errs) == len(s.Relays) {
		return nil, Coverage{}, fmt.Errorf("every chain relay failed: %s", strings.Join(errs, "; "))
	}
	return out, cov, nil
}

// pageLimit is the limit of each REQ. Relays may answer fewer per page.
const pageLimit = 500

// fetch pages one relay's movement events for pubkey, newest first, until a
// page brings nothing new or more than q.Max events that q.Keep keeps are in
// hand (Capped; q.Max <= 0 is no cap). Events Keep drops do not count toward q.Max. A page that fails
// after the first makes the answer Partial; a failed first page is an error.
func (s RelaySource) fetch(ctx context.Context, url, pubkey string, q ChainQuery) ([]nostr.Event, Coverage, error) {
	conn, err := openQuery(ctx, url, s.AuthKey)
	if err != nil {
		return nil, Coverage{}, err
	}
	defer conn.close()

	seen := map[string]bool{}
	var out []nostr.Event
	var until int64
	for page := 0; ; page++ {
		// One event past the cap proves there are more than q.Max.
		if q.Max > 0 && len(out) > q.Max {
			return out[:q.Max], Coverage{Capped: true}, nil
		}
		filter := map[string]interface{}{"authors": []string{pubkey}, "kinds": []int{KindMovement}, "limit": pageLimit}
		for k, v := range q.Tags {
			filter["#"+k] = v
		}
		if len(q.IDs) > 0 {
			filter["ids"] = q.IDs
		}
		if until > 0 {
			filter["until"] = until
		}
		evs, err := conn.page(ctx, "chain"+strconv.Itoa(page), filter)
		if err != nil {
			if page > 0 {
				return out, Coverage{Partial: true}, nil
			}
			return nil, Coverage{}, err
		}
		added := 0
		oldest := int64(0)
		for _, e := range evs {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			added++
			if oldest == 0 || e.CreatedAt < oldest {
				oldest = e.CreatedAt
			}
			if q.Keep == nil || q.Keep(e) {
				out = append(out, e)
			}
		}
		// until is inclusive: the next page repeats the oldest second, and
		// paging stops once a page brings nothing new. A full page that
		// brings nothing new means the relay is not moving back through
		// time (it ignores until, or one second holds more than a page),
		// so what it holds further back is unknown.
		if added == 0 {
			return out, Coverage{Partial: len(evs) >= pageLimit}, nil
		}
		until = oldest
	}
}

// query is one websocket used for a few sequential REQs.
type query struct {
	ws      *websocket.Conn
	url     string
	key     *btcec.PrivateKey
	msgs    chan []json.RawMessage
	readErr chan error
	done    chan struct{}
	once    sync.Once

	mu        sync.Mutex
	challenge string
	authed    bool
}

func openQuery(ctx context.Context, url string, key *btcec.PrivateKey) (*query, error) {
	cfg, err := websocket.NewConfig(url, "http://localhost/")
	if err != nil {
		return nil, err
	}
	cfg.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, err
	}
	q := &query{ws: ws, url: url, key: key, msgs: make(chan []json.RawMessage, 256),
		readErr: make(chan error, 1), done: make(chan struct{})}
	go func() { <-ctx.Done(); ws.Close() }()
	go q.read()
	return q, nil
}

func (q *query) close() {
	q.once.Do(func() { close(q.done) })
	q.ws.Close()
}

func (q *query) read() {
	for {
		var msg string
		if err := websocket.Message.Receive(q.ws, &msg); err != nil {
			q.readErr <- err
			close(q.msgs)
			return
		}
		var arr []json.RawMessage
		if json.Unmarshal([]byte(msg), &arr) != nil || len(arr) < 2 {
			continue
		}
		var typ string
		_ = json.Unmarshal(arr[0], &typ)
		if typ == "AUTH" {
			var ch string
			if json.Unmarshal(arr[1], &ch) == nil {
				q.mu.Lock()
				q.challenge, q.authed = ch, false
				q.mu.Unlock()
			}
			continue
		}
		select {
		case q.msgs <- arr:
		case <-q.done: // nobody is listening any more
			return
		}
	}
}

func (q *query) send(msg []interface{}) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return websocket.Message.Send(q.ws, string(b))
}

// page runs one REQ to EOSE. A CLOSED auth-required is answered with AUTH
// and the REQ is sent once more.
func (q *query) page(ctx context.Context, id string, filter map[string]interface{}) ([]nostr.Event, error) {
	if err := q.send([]interface{}{"REQ", id, filter}); err != nil {
		return nil, err
	}
	var out []nostr.Event
	retried := false
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case arr, ok := <-q.msgs:
			if !ok {
				return nil, fmt.Errorf("connection closed: %v", <-q.readErr)
			}
			var typ, sub string
			_ = json.Unmarshal(arr[0], &typ)
			_ = json.Unmarshal(arr[1], &sub)
			if sub != id {
				continue
			}
			switch typ {
			case "EVENT":
				var e nostr.Event
				if len(arr) >= 3 && json.Unmarshal(arr[2], &e) == nil {
					out = append(out, e)
				}
			case "EOSE":
				_ = q.send([]interface{}{"CLOSE", id})
				return out, nil
			case "CLOSED":
				reason := ""
				if len(arr) >= 3 {
					_ = json.Unmarshal(arr[2], &reason)
				}
				if strings.HasPrefix(reason, "auth-required") && !retried && q.key != nil {
					retried = true
					if err := q.auth(ctx); err != nil {
						return nil, err
					}
					out = nil
					if err := q.send([]interface{}{"REQ", id, filter}); err != nil {
						return nil, err
					}
					continue
				}
				return nil, fmt.Errorf("closed: %s", reason)
			}
		}
	}
}

// auth answers the relay's latest challenge (waiting briefly for one) with a
// signed kind 22242 event and waits for its OK.
func (q *query) auth(ctx context.Context) error {
	deadline := time.Now().Add(3 * time.Second)
	var challenge string
	for {
		q.mu.Lock()
		challenge = q.challenge
		q.mu.Unlock()
		if challenge != "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if challenge == "" {
		return fmt.Errorf("auth required but the relay sent no challenge")
	}
	evt, err := signAuth(q.key, q.url, challenge)
	if err != nil {
		return err
	}
	if err := q.send([]interface{}{"AUTH", evt}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case arr, ok := <-q.msgs:
			if !ok {
				return fmt.Errorf("connection closed during auth")
			}
			var typ, id string
			_ = json.Unmarshal(arr[0], &typ)
			_ = json.Unmarshal(arr[1], &id)
			if typ != "OK" || id != evt.ID {
				continue
			}
			var accepted bool
			if len(arr) >= 3 {
				_ = json.Unmarshal(arr[2], &accepted)
			}
			if !accepted {
				return fmt.Errorf("relay refused our AUTH")
			}
			q.mu.Lock()
			q.authed = true
			q.mu.Unlock()
			return nil
		}
	}
}

// signAuth builds a NIP-42 kind 22242 event for a relay and challenge.
func signAuth(key *btcec.PrivateKey, relay, challenge string) (nostr.Event, error) {
	evt := nostr.Event{
		PubKey:    hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())),
		CreatedAt: time.Now().Unix(),
		Kind:      22242,
		Tags:      [][]string{{"relay", relay}, {"challenge", challenge}},
	}
	sum := sha256.Sum256([]byte(core.SerializeEvent(evt)))
	evt.ID = hex.EncodeToString(sum[:])
	sig, err := schnorr.Sign(key, sum[:])
	if err != nil {
		return nostr.Event{}, err
	}
	evt.Sig = hex.EncodeToString(sig.Serialize())
	return evt, nil
}

// AuthKey parses the key used to answer AUTH challenges (hex or nsec). An
// empty value generates a fresh key: relays that only require *some*
// authenticated reader accept it.
func AuthKey(s string) (*btcec.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return btcec.NewPrivateKey()
	}
	if strings.HasPrefix(s, "nsec1") {
		h, err := tools.DecodeNsec(s)
		if err != nil {
			return nil, err
		}
		s = h
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("auth key must be 64 hex characters or an nsec")
	}
	key, _ := btcec.PrivKeyFromBytes(b)
	return key, nil
}
