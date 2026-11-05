package regiongate

import (
	"context"
	"sync"
	"time"

	nostr "github.com/0ceanslim/grain/server/types"
)

// workQueue runs the gate's chain checks: at most `workers` at once, at most
// `max` units of work waiting, at most `perIP` of them from one client
// address and `perPubkey` distinct movement events for one pubkey. Work for
// one pubkey is one job, so concurrent requests for it share it: readers
// share one check, and the same event sent N times is checked once. Jobs
// are taken round robin across client addresses, oldest first within each,
// so one address flooding the queue delays its own work, not everyone's.
// When a limit is reached the request is refused at once with errBusy,
// which is never cached.
//
// A job runs under its own deadline (check_timeout_seconds), not its
// callers': a caller that stops waiting is told to try again, while the
// check runs on and its verdict is kept for the retry.
type workQueue struct {
	workers, max, perIP, perPubkey int
	timeout                        time.Duration
	run                            func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string)

	mu      sync.Mutex
	jobs    map[string]*job   // by pubkey, queued or running
	byIP    map[string][]*job // queued jobs, oldest first, by the address that queued them
	ring    []string          // addresses with queued jobs, in turn order
	turn    int               // index into ring of the next address served
	queued  int               // units waiting
	ipUnits map[string]int    // units waiting, by address
	running int               // workers running
}

// job is the work waiting or running for one pubkey.
type job struct {
	pubkey  string
	ip      string
	waiters []*waiter
	running bool
}

// waiter is one request: a reader (incoming nil) or a movement event.
type waiter struct {
	incoming *nostr.Event
	ip       string
	units    int
	started  bool
	done     chan struct{}
	ok       bool
	reason   string
}

func newWorkQueue(workers, max, perIP, perPubkey int, timeout time.Duration,
	run func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string)) *workQueue {
	return &workQueue{workers: workers, max: max, perIP: perIP, perPubkey: perPubkey, timeout: timeout, run: run,
		jobs: map[string]*job{}, byIP: map[string][]*job{}, ipUnits: map[string]int{}}
}

// submit queues a check of pubkey, with an incoming movement event or none
// (a reader), for the client at ip ("" when unknown: no per-address limit),
// and waits for its answer until ctx ends.
func (q *workQueue) submit(ctx context.Context, ip, pubkey string, incoming *nostr.Event) (bool, string) {
	w, refusal := q.enqueue(ip, pubkey, incoming)
	if refusal != "" {
		return false, refusal
	}
	select {
	case <-w.done:
		return w.ok, w.reason
	case <-ctx.Done():
		q.mu.Lock()
		started := w.started
		q.mu.Unlock()
		if started {
			return false, errTimeout
		}
		return false, errBusy
	}
}

// pending reports whether a job for pubkey is queued or running.
func (q *workQueue) pending(pubkey string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.jobs[pubkey] != nil
}

func (q *workQueue) enqueue(ip, pubkey string, incoming *nostr.Event) (*waiter, string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[pubkey]
	// A unit is work this request adds: a new job, or a movement event the
	// job does not hold yet. A reader joining a job adds none, and neither
	// does an event already waiting in it.
	units := 1
	if j != nil {
		units = 0
		if incoming != nil {
			distinct := 0
			units = 1
			for _, o := range j.waiters {
				if o.incoming == nil {
					continue
				}
				if o.incoming.ID == incoming.ID {
					units = 0
				}
				distinct++
			}
			if units == 1 && distinct >= q.perPubkey {
				return nil, errBusy
			}
		}
	}
	if units > 0 && (q.queued+units > q.max || ip != "" && q.ipUnits[ip]+units > q.perIP) {
		return nil, errBusy
	}
	w := &waiter{incoming: incoming, ip: ip, units: units, done: make(chan struct{})}
	q.queued += units
	if ip != "" {
		q.ipUnits[ip] += units
	}
	if j == nil {
		j = &job{pubkey: pubkey, ip: ip}
		q.jobs[pubkey] = j
		q.push(j)
	}
	j.waiters = append(j.waiters, w)
	if q.running < q.workers {
		q.running++
		go q.work()
	}
	return w, ""
}

// push puts a queued job at the back of its address's line.
func (q *workQueue) push(j *job) {
	if len(q.byIP[j.ip]) == 0 {
		q.ring = append(q.ring, j.ip)
	}
	q.byIP[j.ip] = append(q.byIP[j.ip], j)
}

// next takes the oldest queued job of the address whose turn it is.
func (q *workQueue) next() *job {
	if len(q.ring) == 0 {
		return nil
	}
	if q.turn >= len(q.ring) {
		q.turn = 0
	}
	ip := q.ring[q.turn]
	line := q.byIP[ip]
	j := line[0]
	if len(line) == 1 {
		delete(q.byIP, ip)
		q.ring = append(q.ring[:q.turn], q.ring[q.turn+1:]...)
	} else {
		q.byIP[ip] = line[1:]
		q.turn++
	}
	return j
}

// work runs queued jobs until none is left. A job's waiters are answered in
// the order they came; one that arrives while its job runs waits for the
// job's next turn.
func (q *workQueue) work() {
	for {
		q.mu.Lock()
		j := q.next()
		if j == nil {
			q.running--
			q.mu.Unlock()
			return
		}
		batch := j.waiters
		j.waiters, j.running = nil, true
		for _, w := range batch {
			w.started = true
		}
		q.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
		type answer struct {
			ok     bool
			reason string
		}
		byEvent := map[string]answer{}
		for _, w := range batch {
			if w.incoming != nil {
				if a, done := byEvent[w.incoming.ID]; done {
					w.ok, w.reason = a.ok, a.reason
					continue
				}
			}
			w.ok, w.reason = q.run(ctx, j.pubkey, w.incoming)
			if w.incoming != nil {
				byEvent[w.incoming.ID] = answer{w.ok, w.reason}
			}
		}
		cancel()

		q.mu.Lock()
		for _, w := range batch {
			q.queued -= w.units
			if w.ip != "" {
				if q.ipUnits[w.ip] -= w.units; q.ipUnits[w.ip] <= 0 {
					delete(q.ipUnits, w.ip)
				}
			}
			close(w.done)
		}
		j.running = false
		if len(j.waiters) > 0 {
			q.push(j)
		} else {
			delete(q.jobs, j.pubkey)
		}
		q.mu.Unlock()
	}
}
