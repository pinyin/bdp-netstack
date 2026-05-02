package tcp

import (
	"time"
)

// ============================================================================
// TimerWheel — BDP orthogonal index for time-based events.
// A simple hash-wheel: N slots, each slot holds a set of Tuples.
// Each slot represents a fixed time interval (e.g., 10ms).
// ============================================================================

type TimerWheel struct {
	slots    []map[Tuple]bool // slot → set of Tuples with timers
	slotSize time.Duration    // duration of each slot
	numSlots int
	cursor   int        // current slot index
	lastTick int64      // last processed tick (monotonic ns, quantized to slot)
}

func NewTimerWheel(slotSize time.Duration, numSlots int) *TimerWheel {
	slots := make([]map[Tuple]bool, numSlots)
	for i := range slots {
		slots[i] = make(map[Tuple]bool)
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

// Schedule adds timer events for a connection at the given absolute tick values.
func (tw *TimerWheel) Schedule(tuple Tuple, tick int64) {
	slot := int(tick % int64(tw.numSlots))
	if slot < 0 {
		slot += tw.numSlots
	}
	tw.slots[slot][tuple] = true
}

// Expired returns tuples whose timers have expired up to the given tick.
// The tick represents the current time quantized to slot size.
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

	// Collect tuples from slots between lastTick+1 and currentTick (inclusive)
	tw.lastTick = currentTick

	// Walk through slots
	for i := start + 1; ; i++ {
		slot := i % tw.numSlots
		for tuple := range tw.slots[slot] {
			expired = append(expired, tuple)
			delete(tw.slots[slot], tuple)
		}
		if slot == end {
			break
		}
	}
	return expired
}
