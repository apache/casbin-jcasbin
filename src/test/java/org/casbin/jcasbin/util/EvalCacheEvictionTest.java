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
import org.casbin.jcasbin.util.CacheEvictionFixtures.ClearAllExpressionCache;
import org.casbin.jcasbin.util.CacheEvictionFixtures.Stats;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.casbin.jcasbin.util.CacheEvictionFixtures.runWorkload;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Eval cache A/B test using deterministic compile counts, not wall-clock timing. The
 * matcher cache is tested in {@code org.casbin.jcasbin.main}.
 */
public class EvalCacheEvictionTest {

    // Bound to production capacity; hot + tail fit so LRU retains hot entries while clear-all thrashes.
    private static final int CAPACITY = BuiltInFunctions.MAX_EVAL_EXPRESSIONS;
    private static final int HOT_COUNT = 8000;
    private static final int ROUNDS = 10;
    private static final int TAILS_PER_ROUND = 1000;

    @Test
    public void testHotExpressionsAreNotRecompiledUnderLru() {
        LruExpressionCache cache = new LruExpressionCache(CAPACITY);
        Stats lru = runWorkload(cache, HOT_COUNT, ROUNDS, TAILS_PER_ROUND);

        assertEquals(lru.hotCompiles, HOT_COUNT,
                "LRU should compile each hot expression exactly once");
        assertTrue(cache.size() <= CAPACITY, "cache must respect its capacity bound");
        assertTrue(lru.evictions > 0, "cold tail entries should be evicted");
    }

    @Test
    public void testClearAllPolicyThrashesHotExpressions() {
        ClearAllExpressionCache baselineCache = new ClearAllExpressionCache(CAPACITY);
        Stats baseline = runWorkload(baselineCache, HOT_COUNT, ROUNDS, TAILS_PER_ROUND);
        LruExpressionCache lruCache = new LruExpressionCache(CAPACITY);
        Stats lru = runWorkload(lruCache, HOT_COUNT, ROUNDS, TAILS_PER_ROUND);

        assertTrue(baseline.hotCompiles >= HOT_COUNT * 2,
                "baseline should reproduce hot-expression thrashing");
        assertTrue(baseline.totalCompiles > lru.totalCompiles,
                "clear-all should compile more than LRU overall");

        System.out.printf("Eval cache A/B (capacity=%d, hot=%d, rounds=%d): "
                        + "clear-all hotCompiles=%d totalCompiles=%d evictions=%d | "
                        + "lru hotCompiles=%d totalCompiles=%d evictions=%d%n",
                CAPACITY, HOT_COUNT, ROUNDS,
                baseline.hotCompiles, baseline.totalCompiles, baseline.evictions,
                lru.hotCompiles, lru.totalCompiles, lru.evictions);
    }

    @Test
    public void testClearInvalidatesEntriesWithoutResettingCounters() {
        LruExpressionCache cache = new LruExpressionCache(4);
        Function<String, Expression> loader = Expression::compile;
        String key = "r_sub == 'a'";

        cache.get(key, loader);
        long compilesBeforeClear = cache.getCompileCount();
        assertEquals(cache.size(), 1);
        assertEquals(compilesBeforeClear, 1);

        cache.clear();
        assertEquals(cache.size(), 0, "clear must drop all cached entries");
        assertEquals(cache.getCompileCount(), compilesBeforeClear,
                "clear must not reset the cumulative compile counter");

        Expression second = cache.get(key, loader);
        assertEquals(cache.getCompileCount(), compilesBeforeClear + 1,
                "a cleared entry must be recompiled on the next miss");
        assertEquals(cache.size(), 1);
        assertNotNull(second, "the recompiled expression must still be usable");
    }

    @Test
    public void testLruRespectsCapacityWithSingleEntryCache() {
        LruExpressionCache cache = new LruExpressionCache(1);
        Function<String, Expression> loader = Expression::compile;
        cache.get("r_sub == 'a'", loader);
        cache.get("r_sub == 'b'", loader);

        assertEquals(cache.size(), 1);
        assertEquals(cache.getCompileCount(), 2);
        assertEquals(cache.getEvictionCount(), 1);
    }

    @Test
    public void testConcurrentMissesCompileEachKeyOnce() throws Exception {
        final LruExpressionCache cache = new LruExpressionCache(CAPACITY);
        final String key = "r_sub == 'shared'";
        final int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Expression>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return cache.get(key, Expression::compile);
                }));
            }
            start.countDown();
            for (Future<Expression> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(cache.getCompileCount(), 1,
                "concurrent misses on the same key must compile exactly once");
        assertEquals(cache.size(), 1);
    }

    @Test
    public void testConcurrentDistinctKeysStayWithinCapacity() throws Exception {
        final int capacity = 32;
        final LruExpressionCache cache = new LruExpressionCache(capacity);
        final int threads = 8;
        final int keysPerThread = 64;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                final int id = t;
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < keysPerThread; i++) {
                        cache.get("r_sub == 't" + id + "_" + i + "'", Expression::compile);
                    }
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertTrue(cache.size() <= capacity, "cache must stay within capacity under concurrent writes");
    }
}
