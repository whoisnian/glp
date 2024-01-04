package cert

import (
	"crypto/x509"
	"sync"
)

type elem struct {
	next *elem
	prev *elem

	name string
	cert *x509.Certificate
}

type SyncCache struct {
	cap  int
	len  int
	root elem

	mu  *sync.Mutex
	idx map[string]*elem
}

func NewSyncCache(cap int) *SyncCache {
	c := &SyncCache{
		cap,
		0,
		elem{},
		&sync.Mutex{},
		make(map[string]*elem),
	}
	c.root.next = &c.root
	c.root.prev = &c.root
	return c
}

func (c *SyncCache) Load(key string) (value *x509.Certificate, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.idx[key]; ok {
		c.moveToFront(e)
		return e.cert, true
	}
	return nil, false
}

func (c *SyncCache) LoadOrStore(key string, value *x509.Certificate) (actual *x509.Certificate, loaded bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.idx[key]; ok {
		c.moveToFront(e)
		return e.cert, true
	} else {
		e = c.pushFront(&elem{name: key, cert: value})
		if c.len > c.cap {
			if ee := c.back(); ee != nil {
				c.remove(ee)
			}
		}
		return e.cert, false
	}
}

func (c *SyncCache) Len() int {
	return c.len
}

func (c *SyncCache) Cap() int {
	return c.cap
}

func (c *SyncCache) back() *elem {
	if c.len == 0 {
		return nil
	}
	return c.root.prev
}

func (c *SyncCache) moveToFront(e *elem) {
	if c.root.next == e {
		return
	}
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = &c.root
	e.next = c.root.next
	e.prev.next = e
	e.next.prev = e
}

func (c *SyncCache) pushFront(e *elem) *elem {
	e.prev = &c.root
	e.next = c.root.next
	e.prev.next = e
	e.next.prev = e
	c.len++
	c.idx[e.name] = e
	return e
}

func (c *SyncCache) remove(e *elem) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil
	e.prev = nil
	e.cert = nil
	delete(c.idx, e.name)
}
