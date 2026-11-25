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

import org.casbin.jcasbin.persist.cache.Cache;
import org.casbin.jcasbin.persist.cache.DefaultCache;
import org.testng.annotations.Test;

import java.time.Duration;

import static org.testng.Assert.*;

public class CachedEnforcerUnitTest {
    private CachedEnforcer cachedEnforcer;

    private Cache cache;

    private void testEnforceCache(String sub, String obj, String act, boolean expectedRes) throws Exception {
        Boolean actualRes = cachedEnforcer.enforce(sub, obj, act);
        assertEquals(actualRes.booleanValue(), expectedRes, String.format("%s, %s, %s: %s, supposed to be %s", sub, obj, act, actualRes, expectedRes));
    }

    @Test
    public void testCache() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        // Test initial policy enforcement
        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("alice", "data1", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);

        // Remove policy and check enforcement results
        cachedEnforcer.removePolicy("alice", "data1", "read");
        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("alice", "data1", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);

        // Initialize another CachedEnforcer with a different model and policy
        cachedEnforcer = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("bob", "data2", "write", true);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        cachedEnforcer.removePolicies(new String[][]{
            {"alice", "data1", "read"},
            {"bob", "data2", "write"},
        });

        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("bob", "data2", "write", false);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        // Re-initialize to ensure policies are loaded correctly
        cachedEnforcer = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("bob", "data2", "write", true);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        // Clear all policies and check results
        cachedEnforcer.clearPolicy();

        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("bob", "data2", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);
    }

    @Test
    public void testInvalidateCache() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv", false);

        Boolean cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

        Boolean actualRes = cachedEnforcer.enforce("alice", "data1", "read");
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertTrue(actualRes, String.format("alice, data1, read: %s, supposed to be %s", actualRes, true));
        assertTrue(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, true));

        cachedEnforcer.invalidateCache();
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

    }

    String getKey(Object... params) {
        return cachedEnforcer.getCacheKey(params);
    }

    @Test
    public void testDefaultCacheIsBounded() {
        DefaultCache boundedCache = new DefaultCache(2);
        boundedCache.set("a", true);
        boundedCache.set("b", true);
        boundedCache.set("b", false);
        assertTrue(boundedCache.get("a"));
        assertFalse(boundedCache.get("b"));

        boundedCache.set("c", true);
        assertNull(boundedCache.get("a"));
        assertNull(boundedCache.get("b"));
        assertTrue(boundedCache.get("c"));

        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        cachedEnforcer.setCache(new DefaultCache(10));
        for (int i = 0; i < 100; i++) {
            cachedEnforcer.enforce("user" + i, "data1", "read");
        }
        int cached = 0;
        for (int i = 0; i < 100; i++) {
            if (cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("user" + i, "data1", "read")) != null) {
                cached++;
            }
        }
        assertTrue(cached <= 10, "cached " + cached + " decisions, supposed to be at most 10");
    }

    @Test
    public void testCacheKeysDoNotCollide() {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        assertNotEquals(cachedEnforcer.getCacheKey("alice$$data1", "read"), cachedEnforcer.getCacheKey("alice", "data1$$read"));
        assertNotEquals(cachedEnforcer.getCacheKey("ab", "c"), cachedEnforcer.getCacheKey("a", "bc"));

        cachedEnforcer.addPolicy("alice$$data1", "read", "write");
        assertTrue(cachedEnforcer.enforce("alice$$data1", "read", "write"));
        assertFalse(cachedEnforcer.enforce("alice", "data1$$read", "write"));

        SyncedCachedEnforcer syncedEnforcer = new SyncedCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        syncedEnforcer.addPolicy("alice$$data1", "read", "write");
        assertTrue(syncedEnforcer.enforce("alice$$data1", "read", "write"));
        assertFalse(syncedEnforcer.enforce("alice", "data1$$read", "write"));
    }

    @Test
    public void testCacheExpiration() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        cache = new DefaultCache();
        cachedEnforcer.setExpireTime(Duration.ofMillis(10));

        // Test cache expiration
        cache.set(getKey("alice", "data1", "read"),true,Duration.ofMillis(10));
        cachedEnforcer.setCache(cache);
        Boolean cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertTrue(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, true));

        // Wait for the cache to expire
        Thread.sleep(15);

        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

        // Replace cache during test run
        cache.clear();
        cache.set(getKey("bob", "data1", "read"),true,Duration.ofMillis(1000));
        cachedEnforcer.setCache(cache);
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("bob", "data1", "read"));
        assertTrue(cacheKey, String.format("bob, data1, read: %s, supposed to be %s", cacheKey, true));

        cache.clear();
        cache.set(getKey("jack", "data1", "write"),true,Duration.ofMillis(1000));
        cachedEnforcer.setCache(cache);
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("bob", "data1", "read"));
        assertNull(cacheKey, String.format("bob, data1, read: %s, supposed to be %s", cacheKey, null));

        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("jack", "data1", "write"));
        assertTrue(cacheKey, String.format("jack, data1, write: %s, supposed to be %s", cacheKey, true));
    }
}
