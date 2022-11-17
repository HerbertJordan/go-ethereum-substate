package lfvm

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

type genHashCacheEntry[K any] struct {
	key        K
	hash       common.Hash
	pred, succ *genHashCacheEntry[K]
}

type genHashCache[K comparable] struct {
	toBytes  func(*K) []byte
	entries  []genHashCacheEntry[K]
	index    map[K]*genHashCacheEntry[K]
	head     *genHashCacheEntry[K]
	tail     *genHashCacheEntry[K]
	nextFree int
	lock     sync.Mutex
}

// newHashCache creates a HashCache with the given capacity of entries.
func newGenHashCache[K comparable](capacity int, toBytes func(*K) []byte) *genHashCache[K] {
	res := &genHashCache[K]{
		toBytes: toBytes,
		entries: make([]genHashCacheEntry[K], capacity),
		index:   make(map[K]*genHashCacheEntry[K], capacity),
	}

	// To avoid the need for handling the special case of an empty cache
	// in every lookup operation we initialize the cache with one value.
	// Since values are never removed, just evicted to make space for another,
	// the cache will never be empty.
	hasher := sha3.NewLegacyKeccak256().(keccakState)

	// Insert first element (all zeros).
	res.head = res.getFree()
	res.tail = res.head

	hasher.Reset()
	var key K
	hasher.Write(toBytes(&key))
	var hash common.Hash
	hasher.Read(hash[:])
	res.head.hash = hash

	res.index[key] = res.head

	return res
}

func (h *genHashCache[K]) getHash(c *context, data []byte) common.Hash {
	var key K
	copy(h.toBytes(&key), data)
	h.lock.Lock()
	if entry, found := h.index[key]; found {
		// Move entry to the front.
		if entry != h.head {
			// Remove from current place.
			entry.pred.succ = entry.succ
			if entry.succ != nil {
				entry.succ.pred = entry.pred
			} else {
				h.tail = entry.pred
			}
			// Add to front
			entry.pred = nil
			entry.succ = h.head
			h.head.pred = entry
			h.head = entry
		}
		h.lock.Unlock()
		return entry.hash
	}

	// Compute the hash without holding the lock.
	h.lock.Unlock()
	hash := getHash(c, data)
	h.lock.Lock()
	defer h.lock.Unlock()

	// We need to check that the key has not be added concurrently.
	if _, found := h.index[key]; found {
		// If it was added concurrently, we are done.
		return hash
	}

	// The key is still not present, so we add it.
	entry := h.getFree()
	entry.key = key
	entry.hash = hash
	entry.pred = nil
	entry.succ = h.head
	h.head.pred = entry
	h.head = entry
	h.index[key] = entry
	return entry.hash
}

func (h *genHashCache[K]) getFree() *genHashCacheEntry[K] {
	// If there are still free entries, use on of those.
	if h.nextFree < len(h.entries) {
		res := &h.entries[h.nextFree]
		h.nextFree++
		return res
	}
	// Use the tail.
	res := h.tail
	h.tail = h.tail.pred
	h.tail.succ = nil
	delete(h.index, res.key)
	return res
}

type GenHashCache struct {
	cache32 *genHashCache[[32]byte]
	cache64 *genHashCache[[64]byte]
}

func newHashCacheGen(capacity32 int, capacity64 int) *GenHashCache {
	return &GenHashCache{
		cache32: newGenHashCache[[32]byte](capacity32, func(data *([32]byte)) []byte { return data[:] }),
		cache64: newGenHashCache[[64]byte](capacity64, func(data *([64]byte)) []byte { return data[:] }),
	}
}

func (h *GenHashCache) hash(c *context, data []byte) common.Hash {
	if len(data) == 32 {
		return h.cache32.getHash(c, data)
	}
	if len(data) == 64 {
		return h.cache64.getHash(c, data)
	}
	return getHash(c, data)
}

type hashCacheEntry32 struct {
	key        [32]byte
	hash       common.Hash
	pred, succ *hashCacheEntry32
}

type hashCacheEntry64 struct {
	key        [64]byte
	hash       common.Hash
	pred, succ *hashCacheEntry64
}

// HashCache is an LRU governed fixed-capacity cache for hash values.
// The cache maintains hashes for hashed input data of size 32 and 64,
// which are the vast majority of values hashed when running EVM
// instructions.
type HashCache struct {
	// Hash infrastructure for 32-byte long inputs.
	entries32      []hashCacheEntry32
	index32        map[[32]byte]*hashCacheEntry32
	head32, tail32 *hashCacheEntry32
	nextFree32     int
	lock32         sync.Mutex

	// Hash infrastructure for 64-byte long inputs.
	entries64      []hashCacheEntry64
	index64        map[[64]byte]*hashCacheEntry64
	head64, tail64 *hashCacheEntry64
	nextFree64     int
	lock64         sync.Mutex

	// Statistics.
	hit, miss int
}

// newHashCache creates a HashCache with the given capacity of entries.
func newHashCache(capacity32 int, capacity64 int) *HashCache {
	res := &HashCache{
		entries32: make([]hashCacheEntry32, capacity32),
		index32:   make(map[[32]byte]*hashCacheEntry32, capacity32),
		entries64: make([]hashCacheEntry64, capacity64),
		index64:   make(map[[64]byte]*hashCacheEntry64, capacity64),
	}

	// To avoid the need for handling the special case of an empty cache
	// in every lookup operation we initialize the cache with one value.
	// Since values are never removed, just evicted to make space for another,
	// the cache will never be empty.
	hasher := sha3.NewLegacyKeccak256().(keccakState)

	// Insert first 32-byte element (all zeros).
	res.head32 = res.getFree32()
	res.tail32 = res.head32

	hasher.Reset()
	var data32 [32]byte
	hasher.Write(data32[:])
	var hash32 common.Hash
	hasher.Read(hash32[:])
	res.head32.hash = hash32

	res.index32[data32] = res.head32

	// Insert first 64-byte element (all zeros).
	res.head64 = res.getFree64()
	res.tail64 = res.head64

	hasher.Reset()
	var data64 [64]byte
	hasher.Write(data64[:])
	var hash64 common.Hash
	hasher.Read(hash64[:])
	res.head64.hash = hash64

	res.index64[data64] = res.head64

	return res
}

// hash fetches a cached hash or computes the hash for the provided data
// using the hasher in the given context.
func (h *HashCache) hash(c *context, data []byte) common.Hash {
	if len(data) == 32 {
		return h.getHash32(c, data)
	}
	if len(data) == 64 {
		return h.getHash64(c, data)
	}
	h.miss++
	return getHash(c, data)
}

func (h *HashCache) getHash32(c *context, data []byte) common.Hash {
	var key [32]byte
	copy(key[:], data)
	h.lock32.Lock()
	if entry, found := h.index32[key]; found {
		h.hit++
		// Move entry to the front.
		if entry != h.head32 {
			// Remove from current place.
			entry.pred.succ = entry.succ
			if entry.succ != nil {
				entry.succ.pred = entry.pred
			} else {
				h.tail32 = entry.pred
			}
			// Add to front
			entry.pred = nil
			entry.succ = h.head32
			h.head32.pred = entry
			h.head32 = entry
		}
		h.lock32.Unlock()
		return entry.hash
	}
	h.miss++

	// Compute the hash without holding the lock.
	h.lock32.Unlock()
	hash := getHash(c, data)
	h.lock32.Lock()
	defer h.lock32.Unlock()

	// We need to check that the key has not be added concurrently.
	if _, found := h.index32[key]; found {
		// If it was added concurrently, we are done.
		return hash
	}

	// The key is still not present, so we add it.
	entry := h.getFree32()
	entry.key = key
	entry.hash = hash
	entry.pred = nil
	entry.succ = h.head32
	h.head32.pred = entry
	h.head32 = entry
	h.index32[key] = entry
	return entry.hash
}

func (h *HashCache) getHash64(c *context, data []byte) common.Hash {
	var key [64]byte
	copy(key[:], data)
	h.lock64.Lock()
	if entry, found := h.index64[key]; found {
		h.hit++
		// Move entry to the front.
		if entry != h.head64 {
			// Remove from current place.
			entry.pred.succ = entry.succ
			if entry.succ != nil {
				entry.succ.pred = entry.pred
			} else {
				h.tail64 = entry.pred
			}
			// Add to front
			entry.pred = nil
			entry.succ = h.head64
			h.head64.pred = entry
			h.head64 = entry
		}
		h.lock64.Unlock()
		return entry.hash
	}
	h.miss++

	// Compute the hash without holding the lock.
	h.lock64.Unlock()
	hash := getHash(c, data)
	h.lock64.Lock()
	defer h.lock64.Unlock()

	// We need to check that the key has not be added concurrently.
	if _, found := h.index64[key]; found {
		// If it was added concurrently, we are done.
		return hash
	}

	// The key is still not present, so we add it.
	entry := h.getFree64()
	entry.key = key
	entry.hash = hash
	entry.pred = nil
	entry.succ = h.head64
	h.head64.pred = entry
	h.head64 = entry
	h.index64[key] = entry
	return entry.hash
}

func (h *HashCache) getFree32() *hashCacheEntry32 {
	// If there are still free entries, use on of those.
	if h.nextFree32 < len(h.entries32) {
		res := &h.entries32[h.nextFree32]
		h.nextFree32++
		return res
	}
	// Use the tail.
	res := h.tail32
	h.tail32 = h.tail32.pred
	h.tail32.succ = nil
	delete(h.index32, res.key)
	return res
}

func (h *HashCache) getFree64() *hashCacheEntry64 {
	// If there are still free entries, use on of those.
	if h.nextFree64 < len(h.entries64) {
		res := &h.entries64[h.nextFree64]
		h.nextFree64++
		return res
	}
	// Use the tail.
	res := h.tail64
	h.tail64 = h.tail64.pred
	h.tail64.succ = nil
	delete(h.index64, res.key)
	return res
}

// getHash computes a Sha3 hash of the given data using the hasher
// instance in the provided context.
func getHash(c *context, data []byte) common.Hash {
	res := common.Hash{}

	if c.hasher == nil {
		c.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		c.hasher.Reset()
	}

	c.hasher.Write(data)
	c.hasher.Read(res[:])
	return res
}
