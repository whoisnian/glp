package ca

import (
	"crypto/tls"
	"sync"
)

// https://github.com/golang/groupcache/blob/master/lru/lru.go
type Cache struct {
	cap  int
	root elem
	idx  map[string]*elem
	mu   *sync.Mutex
}

type elem struct {
	next, prev *elem

	name string
	cert *tls.Certificate
}

func NewCache(cap int) *Cache {
	c := &Cache{
		cap:  cap,
		root: elem{},
		idx:  make(map[string]*elem),
		mu:   &sync.Mutex{},
	}
	c.root.next = &c.root
	c.root.prev = &c.root
	return c
}

func (c *Cache) Load(key string) (value *tls.Certificate, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.idx[key]; ok {
		c.moveToFront(e)
		return e.cert, true
	}
	return nil, false
}

func (c *Cache) LoadOrStore(key string, value *tls.Certificate) (actual *tls.Certificate, loaded bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.idx[key]; ok {
		c.moveToFront(e)
		return e.cert, true
	} else {
		e = c.pushFront(&elem{name: key, cert: value})
		if len(c.idx) > c.cap {
			if ee := c.back(); ee != nil {
				c.remove(ee)
			}
		}
		return e.cert, false
	}
}

func (c *Cache) Status() (length int, capacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.idx), c.cap
}

func (c *Cache) back() *elem {
	if len(c.idx) == 0 {
		return nil
	}
	return c.root.prev
}

func (c *Cache) moveToFront(e *elem) {
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

func (c *Cache) pushFront(e *elem) *elem {
	e.prev = &c.root
	e.next = c.root.next
	e.prev.next = e
	e.next.prev = e
	c.idx[e.name] = e
	return e
}

func (c *Cache) remove(e *elem) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil
	e.prev = nil
	e.cert = nil
	delete(c.idx, e.name)
}
