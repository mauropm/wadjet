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
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

// New creates a Bus.
func New() *Bus { return &Bus{subs: map[chan Event]struct{}{}} }

// Publish sends an event to all subscribers without blocking. Slow consumers
// drop events rather than stalling publishers.
func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe registers a listener; call the returned cancel function when done.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
		close(ch)
	}
}
