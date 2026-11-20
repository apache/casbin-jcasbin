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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Shared A/B fixtures. Lives in {@code util} to read the package-visible counters while
 * exposing a package-independent API.
 */
public final class CacheEvictionFixtures {

    private CacheEvictionFixtures() {
    }

    public static final class Stats {
        public final long hotCompiles;
        public final long totalCompiles;
        public final long evictions;

        public Stats(long hotCompiles, long totalCompiles, long evictions) {
            this.hotCompiles = hotCompiles;
            this.totalCompiles = totalCompiles;
            this.evictions = evictions;
        }
    }

    /** Baseline that reproduces the old clear-all policy, kept in test scope. */
    public static final class ClearAllExpressionCache implements ExpressionCache {
        private final Map<String, Expression> cache = new LinkedHashMap<>();
        private final int capacity;
        private long evictionCount;

        public ClearAllExpressionCache(int capacity) {
            this.capacity = capacity;
        }

        @Override
        public Expression get(String key, Function<String, Expression> loader) {
            Expression expression = cache.get(key);
            if (expression == null) {
                expression = loader.apply(key);
                if (cache.size() >= capacity) {
                    evictionCount += cache.size();
                    cache.clear();
                }
                cache.put(key, expression);
            }
            return expression;
        }

        @Override
        public void clear() {
            cache.clear();
        }

        public long getEvictionCount() {
            return evictionCount;
        }
    }

    public static List<String> hotKeys(int hotCount) {
        List<String> keys = new ArrayList<>(hotCount);
        for (int i = 0; i < hotCount; i++) {
            keys.add("r_sub == 'hot" + i + "'");
        }
        return keys;
    }

    /**
     * Runs the hot-plus-tail workload. Each miss compiles once, so counts are deterministic.
     * Eviction counters are read here (in util) so callers need no package-visible access.
     */
    public static Stats runWorkload(ExpressionCache cache, int hotCount, int rounds, int tailsPerRound) {
        List<String> hotKeys = hotKeys(hotCount);
        Map<String, Integer> compilesByKey = new HashMap<>();
        Function<String, Expression> loader = key -> {
            compilesByKey.merge(key, 1, Integer::sum);
            return Expression.compile(key);
        };

        for (int round = 0; round < rounds; round++) {
            for (String hot : hotKeys) {
                cache.get(hot, loader);
            }
            for (int t = 0; t < tailsPerRound; t++) {
                cache.get("r_sub == 'tail" + round + "_" + t + "'", loader);
            }
        }

        long hotCompiles = 0;
        for (String hot : hotKeys) {
            hotCompiles += compilesByKey.getOrDefault(hot, 0);
        }
        long evictions;
        if (cache instanceof LruExpressionCache) {
            evictions = ((LruExpressionCache) cache).getEvictionCount();
        } else if (cache instanceof ClearAllExpressionCache) {
            evictions = ((ClearAllExpressionCache) cache).getEvictionCount();
        } else {
            evictions = -1;
        }
        return new Stats(hotCompiles, compilesByKey.values().stream().mapToLong(Integer::longValue).sum(),
                evictions);
    }
}
