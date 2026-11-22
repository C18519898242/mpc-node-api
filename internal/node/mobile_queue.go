package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const mobileMailboxLimit = 32

type mobileDelivery struct {
	Sequence uint64          `json:"sequence"`
	Message  json.RawMessage `json:"message"`
}

type mobileMailbox struct {
	mu                            sync.Mutex
	messages                      []mobileDelivery
	next, acknowledged, delivered uint64
	bytes                         int
	changed                       chan struct{}
	expires                       time.Time
}

func newMobileMailbox() *mobileMailbox {
	return &mobileMailbox{changed: make(chan struct{}), expires: time.Now().Add(keygenTimeout + 30*time.Second)}
}

func (b *mobileMailbox) enqueue(message []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(message) > 1<<20 || len(b.messages) >= mobileMailboxLimit || b.bytes+len(message) > 4<<20 {
		return errors.New("mobile message queue is full")
	}
	b.next++
	b.messages = append(b.messages, mobileDelivery{Sequence: b.next, Message: bytes.Clone(message)})
	b.bytes += len(message)
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}

func (b *mobileMailbox) poll(ctx context.Context, ack uint64) (mobileDelivery, error) {
	for {
		b.mu.Lock()
		if ack > b.delivered {
			b.mu.Unlock()
			return mobileDelivery{}, errors.New("invalid mobile acknowledgment")
		}
		if ack > b.acknowledged {
			if len(b.messages) == 0 || b.messages[0].Sequence != ack {
				b.mu.Unlock()
				return mobileDelivery{}, errors.New("invalid mobile acknowledgment")
			}
			b.bytes -= len(b.messages[0].Message)
			b.messages[0] = mobileDelivery{}
			b.messages = b.messages[1:]
			b.acknowledged = ack
		}
		if len(b.messages) > 0 {
			result := b.messages[0]
			b.delivered = result.Sequence
			b.mu.Unlock()
			return result, nil
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return mobileDelivery{}, ctx.Err()
		case <-changed:
		}
	}
}
