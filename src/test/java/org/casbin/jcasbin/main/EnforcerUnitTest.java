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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.EnforceContext;
import org.casbin.jcasbin.util.Util;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.CoreEnforcer.newModel;
import static org.casbin.jcasbin.main.TestUtil.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class EnforcerUnitTest {
    @Test
    public void testKeyMatchModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        Enforcer e = new Enforcer(m, a);

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

        e = new Enforcer(m);
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

        Enforcer e = new Enforcer(m, a);

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

        Enforcer e = new Enforcer(m);

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

        Enforcer e = new Enforcer(m);

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

        Enforcer e = new Enforcer(m);

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

        Enforcer e = new Enforcer(m);

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
    public void testRBACModelInDomain() {
        Enforcer e = new Enforcer("examples/keymatch_with_rbac_in_domain.conf", "examples/keymatch_with_rbac_in_domain.csv");
        testDomainEnforce(e, "Username==test2", "engines/engine1", "*", "attach", true);
    }

    @Test
    public void testInOp() {
        Enforcer e = new Enforcer("examples/in_op_sytanx.conf", "examples/in_op_sytanx.csv");

        TestSub sub = new TestSub("alice");
        TestSub sub2 = new TestSub("alice2");
        TestObj obj = new TestObj(new String[]{"alice", "bob"});

        assertTrue(e.enforce(sub, obj));
        assertFalse(e.enforce(sub2, obj));
    }

    @Test
    public void testReloadPolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        e.loadPolicy();
        testGetPolicy(e, asList(asList("alice", "data1", "read"), asList("bob", "data2", "write"), asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")));
    }

    @Test
    public void testSavePolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.savePolicy();
    }

    @Test
    public void testClearPolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.clearPolicy();
        e.addPolicy("data2_admin", "data2", "read");
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "data2_admin", "data2", "read", true);

        e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");
        e.clearPolicy();
        e.addPolicy("admin", "domain1", "data1", "read");
        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);
    }

    @Test
    public void testEnableEnforce() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

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
    public void testEnableLog() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv", true);
        // The log is enabled by default, so the above is the same with:
        // Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

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
    public void testEnforceExLog() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv", true);

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
        e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv", true);
        testEnforceEx(e, "alice", "data1", "read", true, new String[]{"alice", "data1", "read"});
        testEnforceEx(e, "alice", "data2", "read", true, new String[]{"data2_admin", "data2", "read"});
        testEnforceEx(e, "alice", "data2", "write", true, new String[]{"data2_admin", "data2", "write"});
        testEnforceEx(e, "bob", "data1", "write", false, new String[]{});
        testEnforceEx(e, "bob", "data2", "write", true, new String[]{"bob", "data2", "write"});
    }

    @Test
    public void testEnableAutoSave() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

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
        Enforcer e = new Enforcer("examples/basic_model.conf", adapter);

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
    public void testFileAdapterAutoSave() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        // test addPolicy() autoSave
        e.enableAutoSave(false);
        testEnforce(e, "erica", "data3", "read", false);
        e.addPolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", true);
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", false);

        e.enableAutoSave(true);
        testEnforce(e, "erica", "data3", "read", false);
        e.addPolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", true);
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", true);

        // test removePolicy() autoSave
        e.enableAutoSave(false);
        e.removePolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", false);
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", true);
        e.enableAutoSave(true);
        e.removePolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", false);
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", false);

        // test savePolicy()
        e.enableAutoSave(false);
        e.addPolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", true);
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", false);
        e.addPolicy("erica", "data3", "read");
        testEnforce(e, "erica", "data3", "read", true);
        e.savePolicy();
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", true);
        e.removePolicy("erica", "data3", "read");
        e.savePolicy();
        e.loadPolicy();
        testEnforce(e, "erica", "data3", "read", false);

        // test group policy auto save
        e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        e.enableAutoSave(true);
        testEnforce(e, "alice", "data2", "read", true);
        e.removeGroupingPolicy("alice", "data2_admin");
        testEnforce(e, "alice", "data2", "read", false);
        e.loadPolicy();
        testEnforce(e, "alice", "data2", "read", false);
        e.addGroupingPolicy("alice", "data2_admin");
        e.loadPolicy();
        testEnforce(e, "alice", "data2", "read", true);
    }

    @Test
    public void testRoleLinks() {
        Enforcer e = new Enforcer("examples/rbac_model.conf");
        e.enableAutoBuildRoleLinks(false);
        e.buildRoleLinks();
        e.enforce("user501", "data9", "read");
    }

    @Test
    public void testGetAndSetModel() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new Enforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "root", "data1", "read", false);

        e.setModel(e2.getModel());

        testEnforce(e, "root", "data1", "read", true);
    }

    @Test
    public void testGetAndSetAdapterInMem() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new Enforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv");

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
        Enforcer e = new Enforcer("examples/basic_model.conf");

        testEnforce(e, "alice", "data1", "read", false);

        Adapter a = new FileAdapter("examples/basic_policy.csv");
        e.setAdapter(a);
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", true);
    }

    @Test
    public void testInitEmpty() {
        Enforcer e = new Enforcer();

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
    public void testKeyMatch4Func() {
        Enforcer e = new Enforcer("examples/keymatch4_model.conf", "examples/keymatch4_policy.csv");

        testEnforce(e, "alice", "/alice_data/resource/1/child/1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child/2", "GET", false);

        testEnforce(e, "alice", "/alice_data2/1/using/2", "GET", true);
        testEnforce(e, "alice", "/alice_data2/1/using/1", "GET", true);
        testEnforce(e, "alice", "/alice_data3/1/using/2", "GET", false);

        testEnforce(e, "alice", "/alice_data/resource/1/child/1/child2/1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child2/1/child/1/child2/1", "GET", false);

        testEnforce(e, "alice", "/alice_data/resource/1/child1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child2", "GET", false);
    }

    @Test
    public void testInitEmptyByInputStream() {
        Enforcer e = new Enforcer();

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

    @Test
    public void testEnforceParamCheck() {
        Enforcer e = new Enforcer("examples/rbac_model.conf");
        assertTrue(e.validateEnforce("user501", "data9", "read", "too many params")); //warn only
        assertFalse(e.validateEnforce("data9", "read"));//throw error
    }

    @Test
    public void testGetPermittedActions() {
        Enforcer e = new Enforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv", true);
        String sub = "alice";
        String obj = "data1";
        Set<String> actions = e.getPermittedActions(sub, obj);
        Util.logPrint(sub + " has permissions to access " + obj + " with following actions:");
        for (String action : actions) {
            Util.logPrint(action); //alice should have read-only access to data1
        }

        obj = "data2";

        actions = e.getPermittedActions(sub, obj);
        Util.logPrint(sub + " has permissions to access " + obj + " with following actions:");
        for (String action : actions) {
            Util.logPrint(action); //alice should have read and write access to data2
        }

        e = new Enforcer("examples/abac_model.conf", "", true);
        ModelUnitTest.TestResource data1 = new ModelUnitTest.TestResource("data1", "alice");
        actions = e.getPermittedActions(sub, data1);

        Util.logPrint(sub + " has permissions to access " + data1.name + " with following actions:");
        for (String action : actions) {
            // The result shows that alice should have no access to data1,
            // because no action defines.
            // This method has no meaning for ABAC model,
            // because under this model,
            // the owner of a resource has any permission to the resource it owns.
            Util.logPrint(action);
        }
    }

    @Test
    public void testMultilineModel() {
        Enforcer enforcer = new Enforcer("examples/multiline_model.conf", "examples/multiline_policy.csv");
        testDomainEnforce(enforcer, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(enforcer, "alice", "domain1", "data2", "write", false);
    }

    @Test
    public void testPriorityExplicit() {
        Enforcer e = new Enforcer("examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv");

        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
        testEnforce(e, "data1_deny_group", "data1", "read", false);
        testEnforce(e, "data1_deny_group", "data1", "write", false);
        testEnforce(e, "data2_allow_group", "data2", "read", true);
        testEnforce(e, "data2_allow_group", "data2", "write", true);

        // add a higher priority policy
        e.enableAutoSave(false);
        e.addPolicy("bob", "data2", "write", "deny", "1");

        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
        testEnforce(e, "data1_deny_group", "data1", "read", false);
        testEnforce(e, "data1_deny_group", "data1", "write", false);
        testEnforce(e, "data2_allow_group", "data2", "read", true);
        testEnforce(e, "data2_allow_group", "data2", "write", true);
    }

    @Test
    public void testEnforceWithMatcher() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        // the previous matcher is
        // m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "bob", "data2", "write", true);
        testEnforce(e, "root", "data2", "read", false);
        testEnforce(e, "root", "data3", "read", false);
        testEnforce(e, "jack", "data3", "read", false);

        // custom matcher
        String matcher = "m = r.sub == 'root' || r.sub == p.sub && r.obj == p.obj && r.act == p.act";
        TestUtil.testEnforceWithMatcher(e, matcher, "alice", "data1", "read", true);
        TestUtil.testEnforceWithMatcher(e, matcher, "bob", "data2", "write", true);
        TestUtil.testEnforceWithMatcher(e, matcher, "root", "data2", "read", true);
        TestUtil.testEnforceWithMatcher(e, matcher, "root", "data3", "read", true);
        TestUtil.testEnforceWithMatcher(e, matcher, "jack", "data3", "read", false);
    }

    @Test
    public void testBatchEnforce() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        List<Boolean> results = asList(true, true, false);
        List<Boolean> myResults = e.batchEnforce(asList(asList("alice", "data1", "read"),
            asList("bob", "data2", "write"), asList("jack", "data3", "read")));
        assertEquals(myResults, results);
    }

    @Test
    public void testDomainBatchEnforce() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        List<Boolean> results = asList(true, true, false);
        List<Boolean> myResults = e.batchEnforce(
            asList(
                asList("alice", "domain1", "data1", "read"),
                asList("alice", "domain1", "data1", "write"),
                asList("bob", "domain2", "data1", "write")
            )
        );

        assertEquals(myResults, results);
    }

    @Test
    public void testBatchEnforceWithMatcher() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        // the previous matcher is
        // m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
        String matcher = "m = r.sub == 'root' || r.sub == p.sub && r.obj == p.obj && r.act == p.act";
        List<Boolean> results = asList(true, true, true, true, false);
        List<Boolean> myResults = e.batchEnforceWithMatcher(matcher, asList(asList("alice", "data1", "read"),
            asList("bob", "data2", "write"), asList("root", "data2", "read"),
            asList("root", "data3", "read"), asList("jack", "data3", "read")));
        assertEquals(myResults, results);
    }

    @Test
    public void testMultiplePolicyDefinitions() {
        Enforcer e = new Enforcer("examples/multiple_policy_definitions_model.conf", "examples/multiple_policy_definitions_policy.csv");
        EnforceContext enforceContext = new EnforceContext("2");
        enforceContext.seteType("e");
        testEnforce(e, "alice", "data2", "read", true);
        testEnforceWithContext(e, enforceContext, new AbacAPIUnitTest.TestEvalRule("alice", 70), "/data1", "read", false);
        testEnforceWithContext(e, enforceContext, new AbacAPIUnitTest.TestEvalRule("alice", 30), "/data1", "read", true);
    }

    @Test
    public void testHasLinkSynchronized() {
        File testingDir = null;
        try {
            testingDir = Files.createTempDirectory("testingDir").toFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        File f = null;
        try {
            f = File.createTempFile("policies", null, testingDir);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        FileAdapter a = new FileAdapter(f.getAbsolutePath());

        Enforcer e = new Enforcer("examples/haslink_synchronized_model.conf", a);

        e.enableAutoSave(true);
        e.addNamedMatchingFunc("g", "keyMatch4", BuiltInFunctions::keyMatch4);

        // Add the relationship of gs role
        String[][] gs = new String[1001][3];
        gs[0] = new String[]{"admin@alice.co", "temp", "alice"};
        for (int i = 0; i < 1000; i++) {
            gs[i + 1] = new String[]{i + "@alice.co", "temp", "alice"};
        }
        e.addGroupingPolicies(gs);

        String[][] policy = {{"alice", "/data", "allow"}};
        e.addPolicies(policy);
        e.savePolicy();

        int n = 100;
        CountDownLatch countDownLatch = new CountDownLatch(n);

        for (int i = 0; i < n; i++) {
            int finalI = i;
            new Thread(() -> {
                boolean res = e.enforce("alice", "data");
                if(!res) {
                    System.out.println("result failure: " + finalI);
                }
                countDownLatch.countDown();
            }).start();
        }

        try {
            countDownLatch.await();
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }

        System.out.println("Done!");
    }

    public static class TestSub {
        private String name;

        public TestSub(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    public static class TestAdmins {
        private String name;

        public TestAdmins(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    public static class TestObj {
        private String[] admins;

        public TestObj(String[] admins) {
            this.admins = admins;
        }

        public String[] getAdmins() {
            return admins;
        }

        public void setAdmins(String[] admins) {
            this.admins = admins;
        }
    }
}
