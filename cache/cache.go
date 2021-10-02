package cache

import (
	"container/list"
	"sync"
)

// https://github.com/golang/groupcache/blob/master/lru/lru.go

type SyncCache struct {
	capacity int
	queueMu  *sync.Mutex
	cacheMu  *sync.RWMutex
	queue    *list.List
	cache    map[interface{}]*list.Element
}

type entry struct {
	key   interface{}
	value interface{}
}

func New(capacity int) *SyncCache {
	return &SyncCache{
		capacity,
		&sync.Mutex{},
		&sync.RWMutex{},
		list.New(),
		make(map[interface{}]*list.Element),
	}
}

func (C *SyncCache) Load(key interface{}) (value interface{}, ok bool) {
	C.cacheMu.RLock()
	defer C.cacheMu.RUnlock()

	if ele, ok := C.cache[key]; ok {
		C.queueMu.Lock()
		C.queue.MoveToFront(ele)
		C.queueMu.Unlock()
		return ele.Value.(*entry).value, true
	}
	return nil, false
}

func (C *SyncCache) Store(key, value interface{}) {
	C.cacheMu.Lock()
	defer C.cacheMu.Unlock()

	if ele, ok := C.cache[key]; ok {
		C.queue.MoveToFront(ele)
		ele.Value.(*entry).value = value
	} else {
		ele = C.queue.PushFront(&entry{key, value})
		C.cache[key] = ele
		if C.queue.Len() > C.capacity {
			if ele2 := C.queue.Back(); ele2 != nil {
				C.queue.Remove(ele2)
				e := ele2.Value.(*entry)
				delete(C.cache, e.key)
			}
		}
	}
}

func (C *SyncCache) LoadOrStore(key, value interface{}) (actual interface{}, loaded bool) {
	C.cacheMu.Lock()
	defer C.cacheMu.Unlock()

	if ele, ok := C.cache[key]; ok {
		C.queue.MoveToFront(ele)
		return ele.Value.(*entry).value, true
	} else {
		ele = C.queue.PushFront(&entry{key, value})
		C.cache[key] = ele
		if C.queue.Len() > C.capacity {
			if ele2 := C.queue.Back(); ele2 != nil {
				C.queue.Remove(ele2)
				e := ele2.Value.(*entry)
				delete(C.cache, e.key)
			}
		}
		return value, false
	}
}

func (C *SyncCache) Len() int {
	return C.queue.Len()
}
