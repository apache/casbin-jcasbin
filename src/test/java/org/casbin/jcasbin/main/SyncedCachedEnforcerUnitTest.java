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

import org.casbin.jcasbin.util.Util;
import org.testng.annotations.Test;

import java.time.Duration;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

public class SyncedCachedEnforcerUnitTest {

    private void testSyncEnforceCache(SyncedCachedEnforcer e, String sub, Object obj, String act, boolean res) {
        boolean myRes = e.enforce(sub, obj, act);
        assertEquals(Boolean.valueOf(myRes), Boolean.valueOf(res), String.format("%s, %s, %s: %b, supposed to be %b", sub, obj, act, myRes, res));
    }

    @Test
    public void testSyncCache() throws Exception {
        final SyncedCachedEnforcer enforcer = new SyncedCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        enforcer.setExpireTime(Duration.ofMillis(1));

        int goThread = 1000;
        CountDownLatch latch = new CountDownLatch(goThread);

        for (int i = 0; i < goThread; i++) {
            new Thread(() -> {
                enforcer.addPolicy("alice", "data2", "read");
                testSyncEnforceCache(enforcer, "alice", "data2", "read", true);
                enforcer.invalidateCache();
                latch.countDown();
            }).start();
        }
        latch.await();

        enforcer.removePolicy("alice", "data2", "read");

        testSyncEnforceCache(enforcer, "alice", "data1", "read", true);
        TimeUnit.MILLISECONDS.sleep(2);
        testSyncEnforceCache(enforcer, "alice", "data1", "read", true);

        testSyncEnforceCache(enforcer, "alice", "data1", "write", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "write", false);

        enforcer.removePolicy("alice", "data1", "read");

        testSyncEnforceCache(enforcer, "alice", "data1", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data1", "write", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "write", false);


        SyncedCachedEnforcer syncedCachedEnforcer = new SyncedCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data1", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "bob", "data2", "write", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "write", true);

        syncedCachedEnforcer.removePolicies(new String[][]{
            {"alice", "data1", "read"},
            {"bob", "data2", "write"},
        });

        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data1", "read", false);
        testSyncEnforceCache(syncedCachedEnforcer, "bob", "data2", "write", false);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "write", true);
    }

    private static final String BASIC_MODEL = "[request_definition]\n" +
        "r = sub, obj, act\n" +
        "[policy_definition]\n" +
        "p = sub, obj, act\n" +
        "[policy_effect]\n" +
        "e = some(where (p.eft == allow))\n" +
        "[matchers]\n" +
        "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n";

    @Test
    public void testRevokeDuringConcurrentEnforce() throws Exception {
        boolean enableLog = Util.enableLog;
        Util.enableLog = false;
        Random random = new Random(42);
        int stale = 0;
        try {
            for (int i = 0; i < 200; i++) {
                SyncedCachedEnforcer e = new SyncedCachedEnforcer(CoreEnforcer.newModel(BASIC_MODEL));
                e.addPolicy("alice", "data1", "read");
                e.enforce("alice", "data1", "read");

                AtomicBoolean running = new AtomicBoolean(true);
                Thread load = new Thread(() -> {
                    while (running.get()) {
                        e.enforce("alice", "data1", "read");
                    }
                });
                load.start();
                LockSupport.parkNanos(random.nextInt(60_000));
                e.removePolicy("alice", "data1", "read");
                LockSupport.parkNanos(50_000);
                running.set(false);
                load.join();

                if (e.enforce("alice", "data1", "read")) {
                    stale++;
                }
            }
        } finally {
            Util.enableLog = enableLog;
        }
        assertEquals(stale, 0, "revoked permission was still served from the cache");
    }

    @Test
    public void testRoleRevocationInvalidatesCache() {
        SyncedCachedEnforcer e = new SyncedCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        testSyncEnforceCache(e, "alice", "data2", "read", true);

        e.removeGroupingPolicy("alice", "data2_admin");
        testSyncEnforceCache(e, "alice", "data2", "read", false);

        e.addGroupingPolicy("alice", "data2_admin");
        testSyncEnforceCache(e, "alice", "data2", "read", true);

        e.removePolicy("data2_admin", "data2", "read");
        testSyncEnforceCache(e, "alice", "data2", "read", false);
    }

    @Test
    public void testUncacheableRequestsAreNotShared() {
        SyncedCachedEnforcer e = new SyncedCachedEnforcer("examples/abac_model.conf");
        ModelUnitTest.TestResource data1 = new ModelUnitTest.TestResource("data1", "alice");
        ModelUnitTest.TestResource data2 = new ModelUnitTest.TestResource("data2", "bob");

        testSyncEnforceCache(e, "alice", data1, "read", true);
        testSyncEnforceCache(e, "alice", data2, "read", false);
        assertFalse(e.enforce("bob", data1, "write"));
    }
}
