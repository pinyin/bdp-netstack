package tcp

import (
	"time"
)

// ============================================================================
// TimerWheel — BDP orthogonal index for time-based events.
// A simple hash-wheel: N slots, each slot holds a set of (Tuple, absolute tick).
// Each slot represents a fixed time interval (e.g., 10ms).
// ============================================================================

type slotEntry struct {
	tuple Tuple
	tick  int64 // absolute tick when this timer fires
}

type TimerWheel struct {
	slots    [][]slotEntry // slot → list of (Tuple, absolute tick)
	slotSize time.Duration // duration of each slot
	numSlots int
	cursor   int   // current slot index
	lastTick int64 // last processed tick (monotonic ns, quantized to slot)
}

func NewTimerWheel(slotSize time.Duration, numSlots int) *TimerWheel {
	slots := make([][]slotEntry, numSlots)
	for i := range slots {
		slots[i] = nil
	}
	return &TimerWheel{
		slots:    slots,
		slotSize: slotSize,
		numSlots: numSlots,
		lastTick: time.Now().UnixNano() / int64(slotSize),
	}
}

// SlotDuration returns the duration of each slot.
func (tw *TimerWheel) SlotDuration() time.Duration {
	return tw.slotSize
}

// Advance moves the cursor forward by the elapsed time and returns
// the current tick value.
func (tw *TimerWheel) Advance(now time.Time) int64 {
	tick := now.UnixNano() / int64(tw.slotSize)
	return tick
}

// Schedule adds a timer event for a connection at the given absolute tick.
func (tw *TimerWheel) Schedule(tuple Tuple, tick int64) {
	slot := int(tick % int64(tw.numSlots))
	if slot < 0 {
		slot += tw.numSlots
	}
	tw.slots[slot] = append(tw.slots[slot], slotEntry{tuple: tuple, tick: tick})
}

// Expired returns tuples whose timers have expired up to the given tick.
// Only returns entries whose absolute tick falls within the scanned range.
func (tw *TimerWheel) Expired(currentTick int64) []Tuple {
	if currentTick <= tw.lastTick {
		return nil
	}

	var expired []Tuple
	start := int(tw.lastTick % int64(tw.numSlots))
	if start < 0 {
		start += tw.numSlots
	}
	end := int(currentTick % int64(tw.numSlots))
	if end < 0 {
		end += tw.numSlots
	}

	// Walk through slots from lastTick+1 to currentTick (inclusive)
	for i := start + 1; ; i++ {
		slot := i % tw.numSlots
		remaining := tw.slots[slot][:0]
		for _, entry := range tw.slots[slot] {
			if entry.tick <= currentTick {
				expired = append(expired, entry.tuple)
			} else {
				remaining = append(remaining, entry)
			}
		}
		tw.slots[slot] = remaining
		if slot == end {
			break
		}
	}

	tw.lastTick = currentTick
	return expired
}
