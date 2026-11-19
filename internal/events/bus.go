// Package events provides the in-process publish/subscribe bus that relays
// scan and report progress to Server-Sent Events streams.
package events

import (
	"sync"
)

// Event is one pub/sub message. Topic is a coarse channel (e.g. "scan");
// Kind refines it (e.g. "scan.status"). Subscribers filter on both.
type Event struct {
	Topic   string `json:"topic"`
	Kind    string `json:"kind"`
	Payload any    `json:"payload"`
}

// Bus is a fan-out event bus.
type Bus struct {
	mu    sync.RWMutex
	subs  map[chan Event]struct{}
	drops map[chan Event]int
}

// New creates a Bus.
func New() *Bus {
	return &Bus{subs: map[chan Event]struct{}{}, drops: map[chan Event]int{}}
}

// Publish sends an event to all subscribers without blocking. Slow consumers
// are evicted after slowConsumerLimit consecutive drops rather than being
// allowed to fall arbitrarily behind.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
			b.drops[ch] = 0
		default:
			b.drops[ch]++
			if b.drops[ch] >= slowConsumerLimit {
				delete(b.subs, ch)
				delete(b.drops, ch)
				close(ch) // SSE handler sees the close and the client reconnects
			}
		}
	}
}

const (
	maxSubscribers    = 128 // SEC-012: bound memory/fan-out per process
	slowConsumerLimit = 32  // consecutive drops before a subscriber is evicted
)

// Subscribe registers a listener; call the returned cancel function when done.
// Subscribers that fall behind by slowConsumerLimit drops are evicted so a
// stalled consumer cannot pin memory or silently starve on an unbounded queue.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	if len(b.subs) >= maxSubscribers {
		b.mu.Unlock()
		// Over capacity: hand out a closed channel; the SSE handler treats
		// it as an immediate end-of-stream and the client backs off.
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	ch := make(chan Event, 64)
	b.subs[ch] = struct{}{}
	b.drops[ch] = 0
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		delete(b.drops, ch)
		b.mu.Unlock()
		close(ch)
	}
}
