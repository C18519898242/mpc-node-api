package node

import (
	"context"
	"testing"
	"time"
)

func TestMobileMailboxRedeliveryAndAcknowledgment(t *testing.T) {
	box := newMobileMailbox()
	if err := box.enqueue([]byte(`{"from":"2"}`)); err != nil {
		t.Fatal(err)
	}
	if err := box.enqueue([]byte(`{"from":"3"}`)); err != nil {
		t.Fatal(err)
	}
	first, err := box.poll(t.Context(), 0)
	if err != nil || first.Sequence != 1 {
		t.Fatal("first delivery failed", err)
	}
	retry, err := box.poll(t.Context(), 0)
	if err != nil || retry.Sequence != first.Sequence || string(retry.Message) != string(first.Message) {
		t.Fatal("unacknowledged message was lost", err)
	}
	if _, err := box.poll(t.Context(), 2); err == nil {
		t.Fatal("accepted acknowledgment for an undelivered message")
	}
	second, err := box.poll(t.Context(), 1)
	if err != nil || second.Sequence != 2 {
		t.Fatal("acknowledgment did not advance queue", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, err := box.poll(ctx, 2); err == nil {
		t.Fatal("empty poll ignored cancellation")
	}
}

func TestMobileMailboxLimits(t *testing.T) {
	box := newMobileMailbox()
	if err := box.enqueue(make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("accepted an oversized MPC message")
	}
	for range mobileMailboxLimit {
		if err := box.enqueue([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := box.enqueue([]byte(`{}`)); err == nil {
		t.Fatal("unbounded mobile queue")
	}
}
