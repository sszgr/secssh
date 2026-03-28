package workspace

import (
	"sync"
	"time"
)

type cacheItem struct {
	value     string
	expiresAt time.Time
}

var (
	cacheMu sync.Mutex
	cacheDB = map[string]cacheItem{}
)

func GetCachedPassword(key string, now time.Time) (string, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	item, ok := cacheDB[key]
	if !ok {
		return "", false
	}
	if !item.expiresAt.IsZero() && !item.expiresAt.After(now) {
		delete(cacheDB, key)
		return "", false
	}
	return item.value, true
}

func PutCachedPassword(key, value string, expiresAt time.Time) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cacheDB[key] = cacheItem{value: value, expiresAt: expiresAt}
}

func ClearPasswordCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	clear(cacheDB)
}
