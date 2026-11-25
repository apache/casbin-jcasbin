// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package org.casbin.jcasbin.persist.cache;

import org.casbin.jcasbin.exception.CasbinCacheException;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DefaultCache implements Cache {
    /**
     * The number of decisions a DefaultCache keeps by default.
     */
    public static final int DEFAULT_MAX_ENTRIES = 100000;

    private final Map<String, CacheItem> cache;
    private final int maxEntries;

    public DefaultCache() {
        this(DEFAULT_MAX_ENTRIES);
    }

    /**
     * DefaultCache creates a cache that holds at most maxEntries keys. When the cache is full,
     * adding a new key empties it first. A maxEntries of zero or less means no limit.
     *
     * @param maxEntries the maximum number of keys.
     */
    public DefaultCache(int maxEntries) {
        this.cache = new ConcurrentHashMap<>();
        this.maxEntries = maxEntries;
    }

    /**
     * Set the cache value with an optional time-to-live (TTL).
     *
     * @param key   The cache key to store the value.
     * @param value The boolean value to be stored in the cache.
     * @param ttl   The time-to-live for the cache item; if null or negative, the item will not expire.
     */
    public void set(String key, boolean value, Duration ttl) {
        put(key, new CacheItem(value, ttl));
    }

    /**
     * Set the cache value without a TTL.
     *
     * @param key   The cache key to store the value.
     * @param value The boolean value to be stored in the cache.
     */
    public void set(String key, boolean value) {
        put(key, new CacheItem(value, Duration.ofMillis(-1)));
    }

    private void put(String key, CacheItem item) {
        if (maxEntries > 0 && !cache.containsKey(key) && cache.size() >= maxEntries) {
            cache.clear();
        }
        cache.put(key, item);
    }


    /**
     * Set puts key and value into cache.
     * The first extra parameter should be a java.time.LocalDateTime object denoting the expected survival time.
     * If survival time equals 0 or less, the key will always be valid.
     *
     * @param key   the key to store
     * @param value the value to store
     * @param extra additional parameters (e.g., expiration time)
     * @return true if successful, false otherwise
     */
    @Override
    public boolean set(String key, boolean value, Object... extra) {
        if (extra.length > 0 && extra[0] instanceof Duration) {
            Duration ttl = (Duration) extra[0];
            set(key, value, ttl);
        } else {
            set(key, value);
        }
        return true; // assuming set always succeeds
    }

    /**
     * Get the value from the cache, handling expiration.
     *
     * @param key The cache key to retrieve the value.
     * @throws CasbinCacheException If the key does not exist in the cache.
     * @return The value corresponding to the key.
     */
    public Boolean get(String key) {
        CacheItem item = cache.get(key);
        if (item == null) {
            return null;
        }
        if (item.isExpired()) {
            cache.remove(key, item);
            return null;
        }
        return item.getValue();
    }

    /**
     * Delete the value from the cache.
     *
     * @param key The cache key to delete the value.
     */
    public void delete(String key) throws CasbinCacheException {
        cache.remove(key);
    }

    /**
     * Clear the entire cache.
     */
    public void clear() {
        cache.clear();
    }
}
