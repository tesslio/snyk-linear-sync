package cache

import "context"

// IgnoreMemoryStateKey distinguishes untrusted first loads from an explicitly
// trusted empty memory. It is written before any loader can seed ignore rows.
const IgnoreMemoryStateKey = "ignores_memory_state"
const IgnoreMemoryTrusted = "trusted"
const ignoreMemoryPending = "pending"

type ignoreMemoryStore interface {
	GetMeta(context.Context, string) (string, bool, error)
	SetMeta(context.Context, string, string) error
	HasIgnoreRows(context.Context) (bool, error)
}

// PrepareIgnoreMemory preserves evidence of an empty start across failed loads,
// including diagnostic loads that populate the cache outside Service.Run.
func PrepareIgnoreMemory(ctx context.Context, store ignoreMemoryStore) (bool, error) {
	state, ok, err := store.GetMeta(ctx, IgnoreMemoryStateKey)
	if err != nil {
		return false, err
	}
	if ok {
		return state != IgnoreMemoryTrusted, nil
	}
	present, err := store.HasIgnoreRows(ctx)
	if err != nil {
		return false, err
	}
	state = IgnoreMemoryTrusted
	if !present {
		state = ignoreMemoryPending
	}
	if err := store.SetMeta(ctx, IgnoreMemoryStateKey, state); err != nil {
		return false, err
	}
	return !present, nil
}
