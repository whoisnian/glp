package ca

import (
	"crypto/x509"
	"sync"
)

// https://github.com/golang/groupcache/blob/master/lru/lru.go
type elem struct {
	next *elem
	prev *elem

	name string
	cert *x509.Certificate
}

type Cache struct {
	cap  int
	len  int
	root elem

	mu  *sync.Mutex
	idx map[string]*elem
}

func NewCache(cap int) *Cache {
	c := &Cache{
		cap:  cap,
		len:  0,
		root: elem{},
		mu:   &sync.Mutex{},
		idx:  make(map[string]*elem),
	}
	c.root.next = &c.root
	c.root.prev = &c.root
	return c
}

func (c *Cache) Load(key string) (value *x509.Certificate, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.idx[key]; ok {
		c.moveToFront(e)
		return e.cert, true
	}
	return nil, false
}

func (c *Cache) LoadOrStore(key string, value *x509.Certificate) (actual *x509.Certificate, loaded bool) {
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

func (c *Cache) Len() int {
	return c.len
}

func (c *Cache) Cap() int {
	return c.cap
}

func (c *Cache) back() *elem {
	if c.len == 0 {
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
	c.len++
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
