package workspace

import (
	"testing"
	"time"
)

func TestPasswordCacheHitAndExpire(t *testing.T) {
	ClearPasswordCache()
	now := time.Now()
	PutCachedPassword("k1", "v1", now.Add(2*time.Second))

	v, ok := GetCachedPassword("k1", now)
	if !ok || v != "v1" {
		t.Fatalf("expected cache hit, got ok=%v v=%q", ok, v)
	}

	_, ok = GetCachedPassword("k1", now.Add(3*time.Second))
	if ok {
		t.Fatalf("expected cache miss after expiry")
	}
}
