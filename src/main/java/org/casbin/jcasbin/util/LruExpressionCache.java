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

package org.casbin.jcasbin.util;

import org.casbin.jcasbin.expression.Expression;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * Thread-safe, bounded {@link ExpressionCache} backed by the access-ordered {@link LRUCache}
 * already used by the role managers, so eviction has a single implementation. Counters are
 * package-visible test diagnostics, kept off the public interface.
 */
public final class LruExpressionCache implements ExpressionCache {

    private final LRUCache<String, Expression> cache;
    private final AtomicLong compileCount = new AtomicLong();
    private final AtomicLong evictionCount = new AtomicLong();

    /**
     * @param capacity the maximum number of compiled expressions to retain.
     */
    public LruExpressionCache(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.cache = new LRUCache<>(capacity);
    }

    @Override
    public synchronized Expression get(String key, Function<String, Expression> loader) {
        Expression expression = cache.get(key);
        if (expression == null) {
            expression = loader.apply(key);
            compileCount.incrementAndGet();
            int sizeBeforePut = cache.size();
            cache.put(key, expression);
            if (cache.size() == sizeBeforePut) {
                evictionCount.incrementAndGet();
            }
        }
        return expression;
    }

    @Override
    public synchronized void clear() {
        cache.clear();
        // Counters are cumulative diagnostics and are intentionally not reset here.
    }

    long getCompileCount() {
        return compileCount.get();
    }

    long getEvictionCount() {
        return evictionCount.get();
    }

    synchronized int size() {
        return cache.size();
    }
}
