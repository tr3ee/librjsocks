package librjsocks

import "sync"

/* None BOOL Lock */
type BOOL struct {
	locked bool
	lock   sync.RWMutex
}

func (b *BOOL) True() bool {
	b.lock.RLock()
	if b.locked {
		b.lock.RUnlock()
		return false
	}
	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.locked {
		return false
	}
	b.locked = true
	return true
}

func (b *BOOL) False() bool {
	b.lock.RLock()
	if !b.locked {
		b.lock.RUnlock()
		return false
	}
	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()
	if !b.locked {
		return false
	}
	b.locked = false
	return true
}

func (b *BOOL) Bool() bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.locked
}

func (b *BOOL) RLock() bool {
	b.lock.RLock()
	return b.locked
}

func (b *BOOL) RUnlock() {
	b.lock.RUnlock()
}
