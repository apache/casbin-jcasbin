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

import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.casbin.jcasbin.util.function.CustomFunction;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.CoreEnforcer.newModel;
import static org.casbin.jcasbin.main.TestUtil.*;
import static org.casbin.jcasbin.main.TestUtil.testEnforceEx;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class SyncedEnforcerUnitTest {

    public static void testEnforceSync(SyncedEnforcer e, String sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, obj, act));
    }

    public static void testEnforceSync(SyncedEnforcer e, String sub, Object obj, boolean res) {
        assertEquals(res, e.enforce(sub, obj));
    }

    private static class GateFunction extends CustomFunction {
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        volatile boolean block;

        @Override
        public AviatorObject call(Map<String, Object> env, AviatorObject arg) {
            if (block) {
                entered.countDown();
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return AviatorBoolean.TRUE;
        }

        @Override
        public String getName() {
            return "gate";
        }
    }

    private static SyncedEnforcer newGatedEnforcer(GateFunction gate, boolean hasRole) {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj");
        m.addDef("p", "p", "sub, obj");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "gate(r.sub) && g(r.sub, p.sub) && r.obj == p.obj");
        SyncedEnforcer e = new SyncedEnforcer(m);
        e.addFunction(gate.getName(), gate);
        e.addPolicy("admin", "data");
        if (hasRole) {
            e.addGroupingPolicy("alice", "admin");
        }
        return e;
    }

    @Test
    public void testRoleCacheIsolatedBetweenEnforcers() throws InterruptedException {
        GateFunction gate = new GateFunction();
        SyncedEnforcer isolated = newGatedEnforcer(gate, false);
        SyncedEnforcer privileged = newGatedEnforcer(new GateFunction(), true);
        testEnforceSync(isolated, "alice", "data", false);

        gate.block = true;
        AtomicReference<Boolean> result = new AtomicReference<>();
        Thread t = new Thread(() -> result.set(isolated.enforce("alice", "data")));
        t.start();
        assertTrue(gate.entered.await(10, TimeUnit.SECONDS));
        testEnforceSync(privileged, "alice", "data", true);
        gate.release.countDown();
        t.join(10000);

        assertEquals(result.get(), Boolean.FALSE);
    }

    @Test
    public void testSync(){
        SyncedEnforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        // Start reloading the policy every 200 ms.
        e.startAutoLoadPolicy(TimeUnit.MILLISECONDS.toMillis(200));

        testEnforceSync(e, "alice", "data1", "read", true);
        testEnforceSync(e, "alice", "data1", "write", false);
        testEnforceSync(e, "alice", "data2", "read", false);
        testEnforceSync(e, "alice", "data2", "write", false);
        testEnforceSync(e, "bob", "data1", "read", false);
        testEnforceSync(e, "bob", "data1", "write", false);
        testEnforceSync(e, "bob", "data2", "read", false);
        testEnforceSync(e, "bob", "data2", "write", true);

        // Simulate a policy change
        e.clearPolicy();
        testEnforceSync(e, "bob", "data2", "write", false);

        // Wait for at least one sync
        try {
            TimeUnit.MILLISECONDS.sleep(300);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt(); // restore interrupted status
        }

        testEnforceSync(e, "bob", "data2", "write", true);

        // Stop the reloading policy periodically.
        e.stopAutoLoadPolicy();
    }

    @Test
    public void testStopAutoLoadPolicy(){
        SyncedEnforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        e.startAutoLoadPolicy(TimeUnit.MILLISECONDS.toMillis(5));

        if (!e.isAutoLoadingRunning()){
            System.err.println("auto load is not running");
        }
        e.stopAutoLoadPolicy();
        // Need a moment, to exit goroutine
        try {
            TimeUnit.MILLISECONDS.sleep(10);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        if (e.isAutoLoadingRunning()) {
            System.err.println("auto load is still running");
        }
    }

    @Test
    public void testKeyMatchModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        Enforcer e = new SyncedEnforcer(m, a);

        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource1", "POST", true);
        testEnforce(e, "alice", "/alice_data/resource2", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource2", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource1", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource1", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource2", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource2", "POST", false);

        testEnforce(e, "bob", "/alice_data/resource1", "GET", false);
        testEnforce(e, "bob", "/alice_data/resource1", "POST", false);
        testEnforce(e, "bob", "/alice_data/resource2", "GET", true);
        testEnforce(e, "bob", "/alice_data/resource2", "POST", false);
        testEnforce(e, "bob", "/bob_data/resource1", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource1", "POST", true);
        testEnforce(e, "bob", "/bob_data/resource2", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource2", "POST", true);

        testEnforce(e, "cathy", "/cathy_data", "GET", true);
        testEnforce(e, "cathy", "/cathy_data", "POST", true);
        testEnforce(e, "cathy", "/cathy_data", "DELETE", false);

        e = new SyncedEnforcer(m);
        a.loadPolicy(e.getModel());

        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource1", "POST", true);
        testEnforce(e, "alice", "/alice_data/resource2", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource2", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource1", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource1", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource2", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource2", "POST", false);

        testEnforce(e, "bob", "/alice_data/resource1", "GET", false);
        testEnforce(e, "bob", "/alice_data/resource1", "POST", false);
        testEnforce(e, "bob", "/alice_data/resource2", "GET", true);
        testEnforce(e, "bob", "/alice_data/resource2", "POST", false);
        testEnforce(e, "bob", "/bob_data/resource1", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource1", "POST", true);
        testEnforce(e, "bob", "/bob_data/resource2", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource2", "POST", true);

        testEnforce(e, "cathy", "/cathy_data", "GET", true);
        testEnforce(e, "cathy", "/cathy_data", "POST", true);
        testEnforce(e, "cathy", "/cathy_data", "DELETE", false);
    }

    @Test
    public void testKeyMatchModelInMemoryDeny() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "!some(where (p.eft == deny))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        Enforcer e = new SyncedEnforcer(m, a);

        testEnforce(e, "alice", "/alice_data/resource2", "POST", true);
    }

    @Test
    public void testRBACModelInMemoryIndeterminate() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new SyncedEnforcer(m);

        e.addPermissionForUser("alice", "data1", "invalid");

        testEnforce(e, "alice", "data1", "read", false);
    }

    @Test
    public void testRBACModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new SyncedEnforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");
        e.addPermissionForUser("data2_admin", "data2", "read");
        e.addPermissionForUser("data2_admin", "data2", "write");
        e.addRoleForUser("alice", "data2_admin");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelInMemory2() {
        String text =
		    "[request_definition]\n"
            + "r = sub, obj, act\n"
            + "\n"
            + "[policy_definition]\n"
            + "p = sub, obj, act\n"
            + "\n"
            + "[role_definition]\n"
            + "g = _, _\n"
            + "\n"
            + "[policy_effect]\n"
            + "e = some(where (p.eft == allow))\n"
            + "\n"
            + "[matchers]\n"
            + "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n";

        Model m = newModel(text);
        // The above is the same as:
        // Model m = newModel();
        // m.loadModelFromText(text);

        Enforcer e = new SyncedEnforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");
        e.addPermissionForUser("data2_admin", "data2", "read");
        e.addPermissionForUser("data2_admin", "data2", "write");
        e.addRoleForUser("alice", "data2_admin");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testNotUsedRBACModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new SyncedEnforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testReloadPolicy() {
        Enforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.loadPolicy();
        testGetPolicy(e, asList(asList("alice", "data1", "read"), asList("bob", "data2", "write"), asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")));
    }

    @Test
    public void testSavePolicy() {
        Enforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.savePolicy();
    }

    @Test
    public void testClearPolicy() {
        Enforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.clearPolicy();
    }

    @Test
    public void testEnableEnforce() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        e.enableEnforce(false);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", true);
        testEnforce(e, "bob", "data1", "write", true);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", true);

        e.enableEnforce(true);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testEnforceExLog() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv", true);

        // the previous matcher is
        // m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
        testEnforceEx(e, "alice", "data1", "read", true, new String[]{"alice", "data1", "read"});
        testEnforceEx(e, "bob", "data2", "write", true, new String[]{"bob", "data2", "write"});
        testEnforceEx(e, "root", "data2", "read", false, new String[]{});
        testEnforceEx(e, "root", "data3", "read", false, new String[]{});
        testEnforceEx(e, "jack", "data3", "read", false, new String[]{});

        // custom matcher
        String matcher = "m = r.sub == 'root' || r.sub == p.sub && r.obj == p.obj && r.act == p.act";
        TestUtil.testEnforceExWithMatcher(e, matcher, "alice", "data1", "read", true, new String[]{"alice", "data1", "read"});
        TestUtil.testEnforceExWithMatcher(e, matcher, "bob", "data2", "write", true, new String[]{"bob", "data2", "write"});
        TestUtil.testEnforceExWithMatcher(e, matcher, "root", "data2", "read", true, new String[]{});
        TestUtil.testEnforceExWithMatcher(e, matcher, "root", "data3", "read", true, new String[]{});
        TestUtil.testEnforceExWithMatcher(e, matcher, "jack", "data3", "read", false, new String[]{});

        // the previous matcher is
        // m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
        e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv", true);
        testEnforceEx(e, "alice", "data1", "read", true, new String[]{"alice", "data1", "read"});
        testEnforceEx(e, "alice", "data2", "read", true, new String[]{"data2_admin", "data2", "read"});
        testEnforceEx(e, "alice", "data2", "write", true, new String[]{"data2_admin", "data2", "write"});
        testEnforceEx(e, "bob", "data1", "write", false, new String[]{});
        testEnforceEx(e, "bob", "data2", "write", true, new String[]{"bob", "data2", "write"});
    }

    @Test
    public void testEnableLog() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv", true);
        // The log is enabled by default, so the above is the same with:
        // Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);

        // The log can also be enabled or disabled at run-time.
        e.enableLog(false);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testEnableAutoSave() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        e.enableAutoSave(false);
        // Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
        // it doesn't affect the policy in the storage.
        e.removePolicy("alice", "data1", "read");
        // Reload the policy from the storage to see the effect.
        e.loadPolicy();
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);

        e.enableAutoSave(true);
        testEnforce(e, "bob", "data2", "write", true);
        e.removePolicy("bob", "data2", "write");
        // Affects the policy in the memory
        testEnforce(e, "bob", "data2", "write", false);
        // Affects the policy in the adapter
        // Reload the policy from the storage to see the effect.
        e.loadPolicy();
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
        // prevent previous operations from affecting the CSV file, add the remove policy
        e.addPolicy("bob", "data2", "write");
    }

    @Test
    public void testInitWithAdapter() {
        Adapter adapter = new FileAdapter("examples/basic_policy.csv");
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", adapter);

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRoleLinks() {
        Enforcer e = new SyncedEnforcer("examples/rbac_model.conf");
        e.enableAutoBuildRoleLinks(false);
        e.buildRoleLinks();
        e.enforce("user501", "data9", "read");
    }

    @Test
    public void testGetAndSetModel() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new SyncedEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "root", "data1", "read", false);

        e.setModel(e2.getModel());

        testEnforce(e, "root", "data1", "read", true);
    }

    @Test
    public void testGetAndSetAdapterInMem() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new SyncedEnforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);

        Adapter a2 = e2.getAdapter();
        e.setAdapter(a2);
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", true);
    }

    @Test
    public void testSetAdapterFromFile() {
        Enforcer e = new SyncedEnforcer("examples/basic_model.conf");

        testEnforce(e, "alice", "data1", "read", false);

        Adapter a = new FileAdapter("examples/basic_policy.csv");
        e.setAdapter(a);
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", true);
    }

    @Test
    public void testInitEmpty() {
        Enforcer e = new SyncedEnforcer();

        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        e.setModel(m);
        e.setAdapter(a);
        e.loadPolicy();

        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
    }

    @Test
    public void testInitEmptyByInputStream() {
        Enforcer e = new SyncedEnforcer();

        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        try (FileInputStream fis = new FileInputStream("examples/keymatch_policy.csv")) {
            Adapter a = new FileAdapter(fis);

            e.setModel(m);
            e.setAdapter(a);
            e.loadPolicy();

            testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
