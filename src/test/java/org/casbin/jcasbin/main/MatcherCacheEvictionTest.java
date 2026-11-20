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

package org.casbin.jcasbin.main;

import org.casbin.jcasbin.util.CacheEvictionFixtures.ClearAllExpressionCache;
import org.casbin.jcasbin.util.CacheEvictionFixtures.Stats;
import org.casbin.jcasbin.util.LruExpressionCache;
import org.testng.annotations.Test;

import static org.casbin.jcasbin.util.CacheEvictionFixtures.runWorkload;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Matcher cache A/B test in {@code main} to bind directly to the production constant and
 * assert the concrete cache type, which the A/B comparison alone cannot verify.
 */
public class MatcherCacheEvictionTest {

    private static final int CAPACITY = CoreEnforcer.MAX_CACHED_EXPRESSIONS;
    private static final int HOT_COUNT = CAPACITY * 4 / 5;
    private static final int ROUNDS = 10;
    private static final int TAILS_PER_ROUND = CAPACITY / 10;

    /** Fails if CoreEnforcer is switched back to a non-LRU cache. */
    @Test
    public void testCoreEnforcerUsesLruExpressionCache() {
        CoreEnforcer enforcer = new CoreEnforcer();

        assertTrue(enforcer.expressionCache instanceof LruExpressionCache,
                "CoreEnforcer.expressionCache must be an LruExpressionCache, was: "
                        + enforcer.expressionCache.getClass().getName());
    }

    @Test
    public void testMatcherCacheCapacityAlsoBenefitsFromLru() {
        ClearAllExpressionCache baselineCache = new ClearAllExpressionCache(CAPACITY);
        Stats baseline = runWorkload(baselineCache, HOT_COUNT, ROUNDS, TAILS_PER_ROUND);
        LruExpressionCache lruCache = new LruExpressionCache(CAPACITY);
        Stats lru = runWorkload(lruCache, HOT_COUNT, ROUNDS, TAILS_PER_ROUND);

        assertTrue(baseline.hotCompiles >= HOT_COUNT * 2,
                "clear-all should thrash hot matchers at the matcher cache capacity too");
        assertEquals(lru.hotCompiles, HOT_COUNT,
                "LRU should compile each matcher exactly once at the matcher cache capacity");
        assertTrue(baseline.totalCompiles > lru.totalCompiles,
                "clear-all should compile more than LRU at the matcher cache capacity");

        System.out.printf("Matcher cache A/B (capacity=%d, hot=%d, rounds=%d): "
                        + "clear-all hotCompiles=%d totalCompiles=%d | "
                        + "lru hotCompiles=%d totalCompiles=%d%n",
                CAPACITY, HOT_COUNT, ROUNDS,
                baseline.hotCompiles, baseline.totalCompiles,
                lru.hotCompiles, lru.totalCompiles);
    }
}
