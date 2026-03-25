package util

import "context"

func Done(ctx context.Context) bool {
	select {
	case <-ctx.Done(): return true
	default: return false
	}
}
