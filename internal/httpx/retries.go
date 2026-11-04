package httpx

import "context"

type noRetriesKey struct{}

// WithoutRetries prevents application-level replay of requests with uncertain
// outcomes. It must reach every layer which can replay the request body.
func WithoutRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, noRetriesKey{}, true)
}

func RetriesDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(noRetriesKey{}).(bool)
	return disabled
}
