package speakeasy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0ceanslim/grain/server/db/nostrdb"
	"github.com/0ceanslim/grain/server/utils/log"
)

// ErrClosed is returned by a pool that has been closed (CloseAll).
var ErrClosed = errors.New("relay restarting, try again")

// ErrBusy is returned when a speakeasy's database cannot be opened because
// the cap on open databases is reached and every open one is in use.
var ErrBusy = errors.New("relay busy: too many speakeasies open at once, try again")

// Pool keeps the speakeasy databases (ruling D1): one nostrdb database per
// speakeasy, in its own directory, opened on first use, closed once idle,
// with at most max open at once. A database is never open twice: a request
// for one being closed waits for the close, then opens it again.
//
// Acquire hands out the database with a release function; a database is idle
// only when every acquirer has released it, so a close never pulls one from
// under a query. Callers hold it for one operation (one store, one query),
// not for a connection's life: an open websocket with live subscriptions
// keeps nothing open.
type Pool struct {
	dir  string
	opts nostrdb.Options
	max  int
	idle time.Duration
	open func(dir string, o nostrdb.Options) (*nostrdb.NDB, error)
	now  func() time.Time

	mu    sync.Mutex
	slots map[string]*slot
	// shut is set by CloseAll: nothing opens again. A server restart builds a
	// new pool; connections left over from the old one must not reopen a
	// database the new one may open (LMDB forbids two opens in a process).
	shut bool

	opened, closed atomic.Int64
}

type slot struct {
	id   string
	db   *nostrdb.NDB
	refs int
	last time.Time
	// ready is closed once the open finished (db or err set).
	ready chan struct{}
	err   error
	// closing is set while the database is being closed, and closed when it
	// is.
	closing chan struct{}
}

// NewPool keeps databases under dir, each in dir/<id>, opened with opts
// (IngestThreads is forced to 1), at most max at once, closed after idle.
func NewPool(dir string, opts nostrdb.Options, max int, idle time.Duration) *Pool {
	opts.IngestThreads = IngestThreads
	return &Pool{dir: dir, opts: opts, max: max, idle: idle, open: openDB, now: time.Now, slots: map[string]*slot{}}
}

func openDB(dir string, o nostrdb.Options) (*nostrdb.NDB, error) {
	if err := mkdirAll(dir); err != nil {
		return nil, err
	}
	return nostrdb.OpenWithOptions(dir, o)
}

// Dir is the database directory of a speakeasy.
func (p *Pool) Dir(id string) string { return filepath.Join(p.dir, id) }

// Acquire returns id's database, opening it if needed, and a function that
// releases it (idempotent). It fails with ErrBusy when max databases are open
// and all are in use.
func (p *Pool) Acquire(id string) (*nostrdb.NDB, func(), error) {
	if !validID(id) {
		return nil, nil, errors.New("invalid speakeasy id")
	}
	p.mu.Lock()
	for {
		if p.shut {
			p.mu.Unlock()
			return nil, nil, ErrClosed
		}
		s := p.slots[id]
		if s != nil {
			if s.closing != nil {
				wait := s.closing
				p.mu.Unlock()
				<-wait
				p.mu.Lock()
				continue
			}
			s.refs++
			p.mu.Unlock()
			<-s.ready
			if s.err != nil {
				p.release(s)
				return nil, nil, s.err
			}
			return s.db, p.releaser(s), nil
		}
		if len(p.slots) >= p.max {
			victim := p.idlest()
			if victim == nil {
				p.mu.Unlock()
				return nil, nil, ErrBusy
			}
			wait := p.beginClose(victim)
			p.mu.Unlock()
			<-wait
			p.mu.Lock()
			continue
		}
		s = &slot{id: id, refs: 1, ready: make(chan struct{})}
		p.slots[id] = s
		p.mu.Unlock()

		db, err := p.open(p.Dir(id), p.opts)
		p.mu.Lock()
		if err == nil && p.shut {
			// CloseAll ran while this opened: close it here, as CloseAll
			// could not.
			p.mu.Unlock()
			db.Close()
			p.mu.Lock()
			db, err = nil, ErrClosed
		}
		s.db, s.err = db, err
		if err != nil {
			delete(p.slots, id)
		} else {
			p.opened.Add(1)
		}
		close(s.ready)
		p.mu.Unlock()
		if err != nil {
			log.DB().Error("Speakeasy database failed to open", "id", id, "error", err)
			return nil, nil, err
		}
		return db, p.releaser(s), nil
	}
}

func (p *Pool) releaser(s *slot) func() {
	var once sync.Once
	return func() { once.Do(func() { p.release(s) }) }
}

func (p *Pool) release(s *slot) {
	p.mu.Lock()
	s.refs--
	s.last = p.now()
	p.mu.Unlock()
}

// idlest is the open database used least recently that nothing is using, or
// nil. Called with mu held.
func (p *Pool) idlest() *slot {
	var best *slot
	for _, s := range p.slots {
		if !s.idle() {
			continue
		}
		if best == nil || s.last.Before(best.last) {
			best = s
		}
	}
	return best
}

func (s *slot) idle() bool {
	if s.refs > 0 || s.closing != nil || s.db == nil {
		return false
	}
	select {
	case <-s.ready:
		return true
	default:
		return false
	}
}

// beginClose starts closing an idle slot and returns the channel closed when
// it is closed and gone from the pool. Called with mu held.
func (p *Pool) beginClose(s *slot) chan struct{} {
	s.closing = make(chan struct{})
	go func() {
		s.db.Close()
		p.mu.Lock()
		if p.slots[s.id] == s {
			delete(p.slots, s.id)
		}
		p.closed.Add(1)
		close(s.closing)
		p.mu.Unlock()
	}()
	return s.closing
}

// CloseIdle closes every database nothing has used for the idle time, and
// returns how many it closed.
func (p *Pool) CloseIdle() int {
	p.mu.Lock()
	var waits []chan struct{}
	cutoff := p.now().Add(-p.idle)
	for _, s := range p.slots {
		if s.idle() && !s.last.After(cutoff) {
			waits = append(waits, p.beginClose(s))
		}
	}
	p.mu.Unlock()
	for _, w := range waits {
		<-w
	}
	return len(waits)
}

// Run closes idle databases until ctx ends, then closes them all.
func (p *Pool) Run(ctx context.Context) {
	every := p.idle / 4
	if every < time.Second {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.CloseAll()
			return
		case <-t.C:
			if n := p.CloseIdle(); n > 0 {
				log.DB().Info("Closed idle speakeasy databases", "closed", n, "open", p.Open())
			}
		}
	}
}

// CloseAll closes every open database, waiting for those in use to be
// released by their current operation first (NDB.Close waits for its
// readers; later uses get "nostrdb is closed").
func (p *Pool) CloseAll() {
	p.mu.Lock()
	p.shut = true
	var waits []chan struct{}
	for _, s := range p.slots {
		switch {
		case s.closing != nil:
			waits = append(waits, s.closing)
		case s.db != nil:
			waits = append(waits, p.beginClose(s))
		default:
			// Still opening: its opener sees shut and closes it before
			// ready is closed.
			waits = append(waits, s.ready)
		}
	}
	p.mu.Unlock()
	for _, w := range waits {
		<-w
	}
}

// IsOpen reports whether id's database is open now.
func (p *Pool) IsOpen(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.slots[id]
	return s != nil && s.db != nil && s.closing == nil
}

// Open is how many databases are open (or opening, or closing) now.
func (p *Pool) Open() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.slots)
}

// Opened and Closed count the opens and closes so far.
func (p *Pool) Opened() int64 { return p.opened.Load() }
func (p *Pool) Closed() int64 { return p.closed.Load() }

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }
