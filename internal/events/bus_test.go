package events

import (
	"sync"
	"testing"
	"time"
)

func recvTimeout(t *testing.T, ch <-chan Event) (Event, bool) {
	t.Helper()
	select {
	case e, ok := <-ch:
		return e, ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
		return Event{}, false
	}
}

func TestSubscribePublish(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	defer cancel()

	b.Publish(Event{Topic: "scan", Kind: "scan.status"})
	e, ok := recvTimeout(t, ch)
	if !ok || e.Topic != "scan" || e.Kind != "scan.status" {
		t.Fatalf("got %+v ok=%v", e, ok)
	}
}

// TestEvictionThenCancelNoPanic is the regression test for the double-close
// race: Publish evicts a stalled subscriber by closing its channel; the
// consumer's cancel func must then be a safe no-op, not a second close.
func TestEvictionThenCancelNoPanic(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()

	// Never read from ch: buffer 64 fills, then every further publish is a
	// drop; after slowConsumerLimit consecutive drops Publish evicts+closed.
	for i := 0; i < 64+slowConsumerLimit+1; i++ {
		b.Publish(Event{Topic: "scan", Kind: "k"})
	}
	// Drain buffered events; the channel must reach closed state (eviction),
	// otherwise the drain never terminates and we fail on timeout.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, open := <-ch:
			if !open {
				cancel() // must not panic on the already-closed channel
				return
			}
		case <-deadline:
			t.Fatal("stalled subscriber was not evicted")
		}
	}
}

func TestCancelThenCancelNoPanic(t *testing.T) {
	b := New()
	_, cancel := b.Subscribe()
	cancel()
	cancel() // double cancel must be a no-op, not a double close
}

func TestOverCapacityHandedClosedChannel(t *testing.T) {
	b := New()
	cancels := make([]func(), 0, maxSubscribers)
	for i := 0; i < maxSubscribers; i++ {
		_, c := b.Subscribe()
		cancels = append(cancels, c)
	}
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	ch, cancel := b.Subscribe() // over capacity
	if _, open := <-ch; open {
		t.Fatal("over-capacity subscriber should receive a closed channel")
	}
	cancel() // no-op close path must be safe
}

// TestConcurrentPublishCancel hammers the eviction/cancel race under -race.
func TestConcurrentPublishCancel(t *testing.T) {
	b := New()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() { // publisher
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b.Publish(Event{Topic: "t", Kind: "k"})
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { // churn subscribers, some slow (evicted), some cancel first
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ch, cancel := b.Subscribe()
				if j%2 == 0 {
					// consume a little, then cancel mid-stream
					for k := 0; k < j%7; k++ {
						<-ch
					}
				}
				cancel()
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
