package regiongate

import (
	"context"
	"net"
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
	// runIn, when set, is used instead of run: it is also told the region
	// set the request is judged in (submitIn), which a shared gate needs.
	runIn func(ctx context.Context, pubkey string, incoming *nostr.Event, in *Regions) (bool, string)
	// member, when set, reports whether a pubkey is a known member (an
	// admitted cached entry). Members' jobs are taken before anyone
	// else's, so fresh keys building costly chains cannot starve players.
	member func(pubkey string) bool

	mu sync.Mutex
	// jobs holds the job of each pubkey, queued or running. lines[c] are
	// the queued jobs of class c (0 members, 1 the rest), oldest first, by
	// the address that queued them; rings[c] the addresses with such jobs,
	// in turn order, and turns[c] whose turn is next.
	jobs  map[string]*job
	lines [2]map[string][]*job
	rings [2][]string
	turns [2]int
	// memberRun counts members' jobs taken in a row while anyone else's
	// waited (see unknownEvery).
	memberRun int
	queued    int            // units waiting
	ipUnits   map[string]int // units waiting, by address
	netUnits  map[string]int // units waiting, by network (IPv4 /24, IPv6 /48)
	// classUnits are the units waiting, members' then anyone else's.
	classUnits [2]int
	seq        uint64 // jobs created so far
	running    int    // workers running
}

// job is the work waiting or running for one pubkey.
type job struct {
	pubkey  string
	ip      string
	class   int    // 0 a known member, 1 anyone else
	network string // the network that queued it (networkBucket, or its address)
	seq     uint64 // order of creation: the newest has the highest
	waiters []*waiter
	running bool
}

// waiter is one request: a reader (incoming nil) or a movement event, judged
// in the region set in.
type waiter struct {
	incoming *nostr.Event
	in       *Regions
	ip       string
	network  string
	class    int
	units    int
	started  bool
	done     chan struct{}
	ok       bool
	reason   string
}

func newWorkQueue(workers, max, perIP, perPubkey int, timeout time.Duration,
	run func(ctx context.Context, pubkey string, incoming *nostr.Event) (bool, string)) *workQueue {
	return &workQueue{workers: workers, max: max, perIP: perIP, perPubkey: perPubkey, timeout: timeout, run: run,
		jobs: map[string]*job{}, lines: [2]map[string][]*job{{}, {}}, ipUnits: map[string]int{}, netUnits: map[string]int{}}
}

// submit queues a check of pubkey, with an incoming movement event or none
// (a reader), for the client at ip ("" when unknown: no per-address limit),
// and waits for its answer until ctx ends.
func (q *workQueue) submit(ctx context.Context, ip, pubkey string, incoming *nostr.Event) (bool, string) {
	return q.submitIn(ctx, ip, pubkey, incoming, nil)
}

// submitIn is submit for a request judged in the region set in. Requests
// for one pubkey still share one job whatever their region: the check is the
// same, and each waiter is answered in its own set.
func (q *workQueue) submitIn(ctx context.Context, ip, pubkey string, incoming *nostr.Event, in *Regions) (bool, string) {
	w, refusal := q.enqueue(ip, pubkey, incoming, in)
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

func (q *workQueue) enqueue(ip, pubkey string, incoming *nostr.Event, in *Regions) (*waiter, string) {
	network := networkBucket(ip)
	ip = addressBucket(ip)
	class := 1
	if q.member != nil && q.member(pubkey) {
		class = 0
	}
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
	if j != nil {
		class = j.class
	}
	if units > 0 {
		if ip != "" && q.ipUnits[ip]+units > q.perIP || network != "" && q.netUnits[network]+units > q.perIP*networkShare {
			return nil, errBusy
		}
		if q.queued+units > q.max {
			switch {
			case class == 0:
				// A member is never refused while anyone else holds work: it
				// takes the place of the newest job of the network holding
				// the most, or, when all of theirs is running already (and
				// frees soon), goes over the cap by that much at most: once
				// eviction fails, classUnits[1] is exactly the running part.
				if !q.evict(pubkey, 1) && q.queued+units > q.max+q.classUnits[1] {
					return nil, errBusy
				}
			case ip != "" && q.ipUnits[ip] == 0:
				// An address with nothing waiting takes the place of the
				// newest job of the network holding the most (which keeps
				// some), so every address gets in.
				if !q.evict(pubkey, 2) {
					return nil, errBusy
				}
			default:
				return nil, errBusy
			}
		}
	}
	w := &waiter{incoming: incoming, in: in, ip: ip, network: network, class: class, units: units, done: make(chan struct{})}
	q.hold(w)
	if j == nil {
		q.seq++
		netKey := network
		if netKey == "" {
			netKey = "address " + ip
		}
		j = &job{pubkey: pubkey, ip: ip, class: class, network: netKey, seq: q.seq}
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

// push puts a queued job at the back of its address's line in its class.
func (q *workQueue) push(j *job) {
	c := j.class
	if len(q.lines[c][j.ip]) == 0 {
		q.rings[c] = append(q.rings[c], j.ip)
	}
	q.lines[c][j.ip] = append(q.lines[c][j.ip], j)
}

// unknownEvery bounds members-first: while anyone else's job waits, at
// least every unknownEvery-th job taken is one of theirs. Members keep at
// least three of every four picks under a sustained flood of fresh keys
// (promoting jobs by age instead would let a flood that has waited share
// equally with members, the attack members-first is for), and an unknown
// key waits at most unknownEvery-1 members' jobs once its turn comes.
const unknownEvery = 4

// next takes a known member's job first, if any is queued, else anyone's,
// but anyone else's at least every unknownEvery-th pick while one waits:
// within a class, the oldest job of the address whose turn it is.
func (q *workQueue) next() *job {
	others := len(q.rings[1]) > 0
	order := [2]int{0, 1}
	if others && q.memberRun >= unknownEvery-1 {
		order = [2]int{1, 0}
	}
	for _, c := range order {
		if len(q.rings[c]) == 0 {
			continue
		}
		if q.turns[c] >= len(q.rings[c]) {
			q.turns[c] = 0
		}
		ip := q.rings[c][q.turns[c]]
		line := q.lines[c][ip]
		j := line[0]
		if len(line) == 1 {
			delete(q.lines[c], ip)
			q.rings[c] = append(q.rings[c][:q.turns[c]], q.rings[c][q.turns[c]+1:]...)
		} else {
			q.lines[c][ip] = line[1:]
			q.turns[c]++
		}
		if c == 0 && others {
			q.memberRun++
		} else {
			q.memberRun = 0
		}
		return j
	}
	return nil
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
		// The same event sent again is answered once per region set: an
		// answer for one set is never another's.
		type asked struct {
			id string
			in *Regions
		}
		byEvent := map[asked]answer{}
		for _, w := range batch {
			if w.incoming != nil {
				if a, done := byEvent[asked{w.incoming.ID, w.in}]; done {
					w.ok, w.reason = a.ok, a.reason
					continue
				}
			}
			if q.runIn != nil {
				w.ok, w.reason = q.runIn(ctx, j.pubkey, w.incoming, w.in)
			} else {
				w.ok, w.reason = q.run(ctx, j.pubkey, w.incoming)
			}
			if w.incoming != nil {
				byEvent[asked{w.incoming.ID, w.in}] = answer{w.ok, w.reason}
			}
		}
		cancel()

		q.mu.Lock()
		for _, w := range batch {
			q.release(w)
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

// liveBucket is the address the background checks of LiveAllowed queue
// under, so they count against a per-address limit like any client's.
const liveBucket = "live"

// addressBucket is the unit the per-address limit counts: an IPv4 address
// (an IPv4-mapped IPv6 address counts as its IPv4 one), or an IPv6
// address's /64, since one host is usually given a whole /64 and
// could otherwise take a fresh address for every request. Anything else
// (the live bucket, an unreadable address) counts as itself.
func addressBucket(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ip
	}
	if v4 := a.To4(); v4 != nil { // IPv4, or IPv4-mapped IPv6 (::ffff:a.b.c.d)
		return v4.String()
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// networkShare: one network (an IPv4 /24, an IPv6 /48) may have at most
// networkShare times max_queued_per_ip units waiting, so a host with many
// addresses (a /56 holds 256 /64s) cannot fill the queue on its own.
const networkShare = 4

// networkBucket is the network the per-network limit counts, or "" for
// anything that is not an address (the live bucket).
func networkBucket(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if v4 := a.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return a.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

func (q *workQueue) hold(w *waiter) {
	q.queued += w.units
	q.classUnits[w.class] += w.units
	if w.ip != "" {
		q.ipUnits[w.ip] += w.units
	}
	if w.network != "" {
		q.netUnits[w.network] += w.units
	}
}

func (q *workQueue) release(w *waiter) {
	q.queued -= w.units
	q.classUnits[w.class] -= w.units
	if w.ip != "" {
		if q.ipUnits[w.ip] -= w.units; q.ipUnits[w.ip] <= 0 {
			delete(q.ipUnits, w.ip)
		}
	}
	if w.network != "" {
		if q.netUnits[w.network] -= w.units; q.netUnits[w.network] <= 0 {
			delete(q.netUnits, w.network)
		}
	}
}

// evict drops the newest queued job (not one running) of a non-member,
// from the network (IPv4 /24, IPv6 /48) whose queued non-member jobs hold
// the most units, when that network holds at least min of them; its
// waiters are told "busy, try again", which is never cached. Choosing by
// network rather than by address means filling the door with one-unit
// addresses takes as many networks as the queue holds units. A job of
// pubkey itself is never dropped. It reports whether one was.
func (q *workQueue) evict(pubkey string, min int) bool {
	units := map[string]int{}
	for _, ip := range q.rings[1] {
		for _, j := range q.lines[1][ip] {
			for _, w := range j.waiters {
				units[j.network] += w.units
			}
		}
	}
	best, bestUnits := "", 0
	for n, u := range units {
		if u > bestUnits || u == bestUnits && n < best {
			best, bestUnits = n, u
		}
	}
	if best == "" || bestUnits < min {
		return false
	}
	var victim *job
	at := -1
	for _, ip := range q.rings[1] {
		for i, j := range q.lines[1][ip] {
			if j.network == best && j.pubkey != pubkey && (victim == nil || j.seq > victim.seq) {
				victim, at = j, i
			}
		}
	}
	if victim == nil {
		return false
	}
	ip := victim.ip
	line := q.lines[1][ip]
	q.lines[1][ip] = append(line[:at:at], line[at+1:]...)
	if len(q.lines[1][ip]) == 0 {
		delete(q.lines[1], ip)
		for k, a := range q.rings[1] {
			if a == ip {
				q.rings[1] = append(q.rings[1][:k], q.rings[1][k+1:]...)
				if k < q.turns[1] {
					q.turns[1]--
				}
				break
			}
		}
	}
	delete(q.jobs, victim.pubkey)
	for _, w := range victim.waiters {
		q.release(w)
		w.ok, w.reason = false, errBusy
		close(w.done)
	}
	victim.waiters = nil
	return true
}
