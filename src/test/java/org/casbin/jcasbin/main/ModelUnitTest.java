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

import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.file_adapter.AdapterMock;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.Util;
import org.casbin.jcasbin.util.function.CustomFunction;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforceWithoutUsers;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class ModelUnitTest {
    @Test
    public void testBasicModel() {
        Enforcer e = new Enforcer("examples/basic_model_without_spaces.conf", "examples/basic_policy.csv");

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
    public void testBasicModelWithoutSpaces() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

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
    public void testBasicModelNoPolicy() {
        Enforcer e = new Enforcer("examples/basic_model.conf");

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
    }

    @Test
    public void testBasicModelWithRoot() {
        Enforcer e = new Enforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
        testEnforce(e, "root", "data1", "read", true);
        testEnforce(e, "root", "data1", "write", true);
        testEnforce(e, "root", "data2", "read", true);
        testEnforce(e, "root", "data2", "write", true);
    }

    @Test
    public void testBasicModelWithRootNoPolicy() {
        Enforcer e = new Enforcer("examples/basic_with_root_model.conf");

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
        testEnforce(e, "root", "data1", "read", true);
        testEnforce(e, "root", "data1", "write", true);
        testEnforce(e, "root", "data2", "read", true);
        testEnforce(e, "root", "data2", "write", true);
    }

    @Test
    public void testBasicModelWithoutUsers() {
        Enforcer e = new Enforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv");

        testEnforceWithoutUsers(e, "data1", "read", true);
        testEnforceWithoutUsers(e, "data1", "write", false);
        testEnforceWithoutUsers(e, "data2", "read", false);
        testEnforceWithoutUsers(e, "data2", "write", true);
    }

    @Test
    public void testBasicModelWithoutResources() {
        Enforcer e = new Enforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv");

        testEnforceWithoutUsers(e, "alice", "read", true);
        testEnforceWithoutUsers(e, "alice", "write", false);
        testEnforceWithoutUsers(e, "bob", "read", false);
        testEnforceWithoutUsers(e, "bob", "write", true);
    }

    @Test
    public void testRBACModel() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

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
    public void testRBACModelWithResourceRoles() {
        Enforcer e = new Enforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithDomains() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testResourceMatchingDoesNotEnableDomainMatching() {
        Model m = new Model();
        m.addDef("r", "r", "sub, obj, act, dom");
        m.addDef("p", "p", "sub, obj, act, dom");
        m.addDef("g", "g", "_, _, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && r.act == p.act");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "/data/*", "read", "tenantA");
        e.addGroupingPolicy("alice", "admin", "tenant*");
        e.addGroupingPolicy("bob", "admin", "tenantA");

        assertFalse(e.enforce("alice", "/data/1", "read", "tenantA"));
        assertTrue(e.enforce("bob", "/data/1", "read", "tenantA"));

        e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        assertTrue(e.enforce("alice", "/data/1", "read", "tenantA"));
    }

    @DataProvider(name = "domainRoleCalls")
    public Object[][] domainRoleCalls() {
        return new Object[][] {
            {"g2(r.sub,p.sub,r.tenant)"},
            {"g2((r.sub),'admin',r.tenant)"}
        };
    }

    @Test(dataProvider = "domainRoleCalls")
    public void testDomainMatchingUsesRoleDomainArgument(String roleCall) {
        Model m = new Model();
        m.addDef("r", "r", "sub, obj, act, tenant");
        m.addDef("p", "p", "sub, obj, act, tenant");
        m.addDef("g", "g2", "_, _, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", roleCall + " && keyMatch(r.tenant,p.tenant) && r.obj == p.obj && r.act == p.act");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "data", "read", "tenant*");
        e.addNamedGroupingPolicy("g2", "alice", "admin", "tenant*");

        assertTrue(e.enforce("alice", "data", "read", "tenantA"));
        assertFalse(e.enforce("alice", "data", "read", "other"));
        assertFalse(e.enforce("bob", "data", "read", "tenantA"));
    }

    @Test
    public void testQuotedDomainMatcherDoesNotEnableDomainMatching() {
        Model m = new Model();
        m.addDef("r", "r", "sub, dom, obj, act");
        m.addDef("p", "p", "sub, dom, obj, act");
        m.addDef("g", "g", "_, _, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act && r.obj != 'keyMatch(r_dom, p_dom)'");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "tenantA", "data", "read");
        e.addGroupingPolicy("alice", "admin", "tenant*");
        e.addGroupingPolicy("bob", "admin", "tenantA");

        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.enforce("bob", "tenantA", "data", "read"));
    }

    @Test
    public void testConditionalDomainMatchingPreservesConditions() {
        Model m = new Model();
        m.addDef("r", "r", "sub, dom, obj, act");
        m.addDef("p", "p", "sub, dom, obj, act");
        m.addDef("g", "g", "_, _, _, (_, _)");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "tenantA", "data", "read");
        e.addPolicy("admin", "tenantB", "data", "read");
        e.addGroupingPolicy("alice", "admin", "tenant*", "deny", "_");
        e.addGroupingPolicy("bob", "reader", "tenantA", "_", "_");
        e.addNamedDomainLinkConditionFunc("g", "alice", "admin", "tenant*", params -> "allow".equals(params[0]));
        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "deny", "_");

        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));

        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "allow", "_");
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.enforce("alice", "tenantB", "data", "read"));

        e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.enforce("alice", "tenantB", "data", "read"));

        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "deny", "_");
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));
    }

    @DataProvider(name = "conditionalRoleMatching")
    public Object[][] conditionalRoleMatching() {
        return new Object[][] {{"g", false}, {"g2", false}, {"g", true}, {"g2", true}};
    }

    @Test(dataProvider = "conditionalRoleMatching")
    public void testNamedRoleMatchingPreservesConditions(String ptype, boolean withDomain) {
        Model m = new Model();
        m.addDef("r", "r", "sub, dom, obj, act");
        m.addDef("p", "p", "sub, dom, obj, act");
        m.addDef("g", ptype, withDomain ? "_, _, _, (_, _)" : "_, _, (_, _)");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", ptype + (withDomain ? "(r.sub, p.sub, r.dom)" : "(r.sub, p.sub)")
            + " && r.dom == p.dom && r.obj == p.obj && r.act == p.act");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "tenantA", "data", "read");
        if (withDomain) {
            e.addNamedGroupingPolicy(ptype, "alice", "admin", "tenantA", "deny", "_");
            e.addNamedGroupingPolicy(ptype, "bob*", "admin", "tenantA", "_", "_");
            e.addNamedDomainLinkConditionFunc(ptype, "alice", "admin", "tenantA", params -> "allow".equals(params[0]));
            e.setNamedDomainLinkConditionFuncParams(ptype, "alice", "admin", "tenantA", "deny", "_");
        } else {
            e.addNamedGroupingPolicy(ptype, "alice", "admin", "deny", "_");
            e.addNamedGroupingPolicy(ptype, "bob*", "admin", "_", "_");
            e.addNamedLinkConditionFunc(ptype, "alice", "admin", params -> "allow".equals(params[0]));
            e.setNamedLinkConditionFuncParams(ptype, "alice", "admin", "deny", "_");
        }
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("bob1", "tenantA", "data", "read"));

        assertTrue(e.addNamedMatchingFunc(ptype, "keyMatch", BuiltInFunctions::keyMatch));
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.enforce("bob1", "tenantA", "data", "read"));
        assertTrue(e.addNamedMatchingFunc(ptype, "keyMatch", BuiltInFunctions::keyMatch));
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));

        if (withDomain) {
            e.setNamedDomainLinkConditionFuncParams(ptype, "alice", "admin", "tenantA", "allow", "_");
        } else {
            e.setNamedLinkConditionFuncParams(ptype, "alice", "admin", "allow", "_");
        }
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.addNamedMatchingFunc(ptype, "exact", String::equals));
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("bob1", "tenantA", "data", "read"));
    }

    @DataProvider(name = "conditionalDomainReconfiguration")
    public Object[][] conditionalDomainReconfiguration() {
        return new Object[][] {{false, false}, {false, true}, {true, false}, {true, true}};
    }

    @Test(dataProvider = "conditionalDomainReconfiguration")
    public void testConditionalDomainMatchingCanBeNarrowed(boolean matchBeforeLinks, boolean existingDomain) {
        Model m = new Model();
        m.addDef("r", "r", "sub, dom, obj, act");
        m.addDef("p", "p", "sub, dom, obj, act");
        m.addDef("g", "g", "_, _, _, (_, _)");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act");
        Enforcer e = new Enforcer(m);
        e.addPolicy("admin", "tenantA", "data", "read");
        e.addPolicy("admin", "tenantB", "data", "read");
        e.addPolicy("admin", "tenant*", "data", "read");
        if (matchBeforeLinks) {
            e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        }
        if (existingDomain) {
            e.addGroupingPolicy("bob", "admin", "tenantA", "_", "_");
        }
        e.addGroupingPolicy("alice", "admin", "tenant*", "deny", "_");
        e.addNamedDomainLinkConditionFunc("g", "alice", "admin", "tenant*", params -> "allow".equals(params[0]));
        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "deny", "_");
        if (!matchBeforeLinks) {
            e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        }
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));

        e.addNamedDomainMatchingFunc("g", "exact", String::equals);
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));
        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "allow", "_");
        assertTrue(e.enforce("alice", "tenant*", "data", "read"));
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));

        e.addNamedDomainMatchingFunc("g", "keyMatch", BuiltInFunctions::keyMatch);
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.enforce("alice", "tenantB", "data", "read"));
        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "deny", "_");
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));
        e.setNamedDomainLinkConditionFuncParams("g", "alice", "admin", "tenant*", "allow", "_");
        assertTrue(e.enforce("alice", "tenantA", "data", "read"));
        assertTrue(e.removeGroupingPolicy("alice", "admin", "tenant*", "deny", "_"));
        assertFalse(e.enforce("alice", "tenantA", "data", "read"));
        assertFalse(e.enforce("alice", "tenantB", "data", "read"));
        assertEquals(e.enforce("bob", "tenantA", "data", "read"), existingDomain);
    }

    @Test
    public void testRBACModelWithDomainsAtRuntime() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf");

        e.addPolicy("admin", "domain1", "data1", "read");
        e.addPolicy("admin", "domain1", "data1", "write");
        e.addPolicy("admin", "domain2", "data2", "read");
        e.addPolicy("admin", "domain2", "data2", "write");

        e.addGroupingPolicy("alice", "admin", "domain1");
        e.addGroupingPolicy("bob", "admin", "domain2");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);

        // Remove all policy rules related to domain1 and data1.
        e.removeFilteredPolicy(1, "domain1", "data1");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);

        // Remove the specified policy rule.
        e.removePolicy("admin", "domain2", "data2", "read");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithDomainsAtRuntimeMockAdapter(){
        AdapterMock adapter = new AdapterMock("examples/rbac_with_domains_policy.csv");
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", adapter);

        e.addPolicy("admin", "domain3", "data1", "read");
        e.addGroupingPolicy("alice", "admin", "domain3");

        testDomainEnforce(e, "alice", "domain3", "data1", "read", true);

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        e.removeFilteredPolicy(1, "domain1", "data1");
        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);

        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        e.removePolicy("admin", "domain2", "data2", "read");
        testDomainEnforce(e, "bob", "domain2", "data2", "read", false);
    }

    @Test
    public void testRBACModelWithDeny() {
        Enforcer e = new Enforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithOnlyDeny() {
        Enforcer e = new Enforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv");

        testEnforce(e, "alice", "data2", "write", false);
    }

    @Test
    public void testRBACModelWithCustomData() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        // You can add custom data to a grouping policy, Casbin will ignore it. It is only
        // meaningful to the caller.
        // This feature can be used to store information like whether "bob" is an end user (so no
        // subject will inherit "bob")
        // For Casbin, it is equivalent to: e.addGroupingPolicy("bob", "data2_admin")
        e.addGroupingPolicy("bob", "data2_admin", "custom_data");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", true);

        // You should also take the custom data as a parameter when deleting a grouping policy.
        // e.removeGroupingPolicy("bob", "data2_admin") won't work.
        // Or you can remove it by using removeFilteredGroupingPolicy().
        e.removeGroupingPolicy("bob", "data2_admin", "custom_data");

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
    public void testRBACModelWithPattern(){
        Enforcer e = new Enforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv");

        // Here's a little confusing: the matching function here is not the custom function used in matcher.
        // It is the matching function used by "g" (and "g2", "g3" if any..)
        // You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
        // of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
        // You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
        e.addNamedMatchingFunc("g2", "KeyMatch2", BuiltInFunctions::keyMatch2);
        e.addNamedMatchingFunc("g", "KeyMatch2", BuiltInFunctions::keyMatch2);
        testEnforce(e, "any_user", "/pen3/1", "GET", true);
        testEnforce(e, "/book/user/1", "/pen4/1", "GET", true);

        testEnforce(e, "/book/user/1", "/pen4/1", "POST", true);

        testEnforce(e, "alice", "/book/1", "GET", true);
        testEnforce(e, "alice", "/book/2", "GET", true);
        testEnforce(e, "alice", "/pen/1", "GET", true);
        testEnforce(e, "alice", "/pen/2", "GET", false);
        testEnforce(e, "bob", "/book/1", "GET", false);
        testEnforce(e, "bob", "/pen/1", "GET", true);
        testEnforce(e, "bob", "/pen/2", "GET", true);

        // AddMatchingFunc() is actually setting a function because only one function is allowed,
        // so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
        e.addNamedMatchingFunc("g2", "KeyMatch2", BuiltInFunctions::keyMatch3);
        testEnforce(e, "alice", "/book2/1", "GET", true);
        testEnforce(e, "alice", "/book2/2", "GET", true);
        testEnforce(e, "alice", "/pen2/1", "GET", true);
        testEnforce(e, "alice", "/pen2/2", "GET", false);
        testEnforce(e, "bob", "/book2/1", "GET", false);
        testEnforce(e, "bob", "/book2/2", "GET", false);
        testEnforce(e, "bob", "/pen2/1", "GET", true);
        testEnforce(e, "bob", "/pen2/2", "GET", true);
    }

    class CustomRoleManager implements RoleManager {
        @Override
        public void clear() {
        }

        @Override
        public void addLink(String name1, String name2, String... domain) {
        }

        @Override
        public void deleteLink(String name1, String name2, String... domain) {
        }

        @Override
        public boolean hasLink(String name1, String name2, String... domain) {
            if (name1.equals("alice") && name2.equals("alice")) {
                return true;
            } else if (name1.equals("alice") && name2.equals("data2_admin")) {
                return true;
            } else if (name1.equals("bob") && name2.equals("bob")) {
                return true;
            }
            return false;
        }

        @Override
        public List<String> getRoles(String name, String... domain) {
            return null;
        }

        @Override
        public List<String> getUsers(String name, String... domain) {
            return null;
        }

        @Override
        public void printRoles() {
        }
    }

    @Test
    public void testRBACModelWithCustomRoleManager() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        e.setRoleManager(new CustomRoleManager());
        e.loadModel();
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    public static class TestResource {
        String name;
        String owner;

        public TestResource(String name, String owner) {
            this.name = name;
            this.owner = owner;
        }

        public String getName() {
            return name;
        }

        public String getOwner() {
            return owner;
        }
    }

    @Test
    public void testABACModel() {
        Enforcer e = new Enforcer("examples/abac_model.conf");

        TestResource data1 = new TestResource("data1", "alice");
        TestResource data2 = new TestResource("data2", "bob");

        testEnforce(e, "alice", data1, "read", true);
        testEnforce(e, "alice", data1, "write", true);
        testEnforce(e, "alice", data2, "read", false);
        testEnforce(e, "alice", data2, "write", false);
        testEnforce(e, "bob", data1, "read", false);
        testEnforce(e, "bob", data1, "write", false);
        testEnforce(e, "bob", data2, "read", true);
        testEnforce(e, "bob", data2, "write", true);
    }

    @Test
    public void testABACMapRequest(){
        Enforcer e = new Enforcer("examples/abac_model.conf");

        Map<String, Object> data1 = new HashMap<>();
        data1.put("Name", "data1");
        data1.put("Owner", "alice");

        Map<String, Object> data2 = new HashMap<>();
        data2.put("Name", "data2");
        data2.put("Owner", "bob");

        testEnforce(e, "alice", data1, "read", true);
        testEnforce(e, "alice", data1, "write", true);
        testEnforce(e, "alice", data2, "read", false);
        testEnforce(e, "alice", data2, "write", false);
        testEnforce(e, "bob", data1, "read", false);
        testEnforce(e, "bob", data1, "write", false);
        testEnforce(e, "bob", data2, "read", true);
        testEnforce(e, "bob", data2, "write", true);
    }

    static class StructRequest {
        private List<Object> Roles;
        private boolean Enabled;
        private int Age;
        private String Name;

        // Getters and setters
        public List<Object> getRoles() {
            return Roles;
        }

        public void setRoles(List<Object> Roles) {
            this.Roles = Roles;
        }

        public boolean isEnabled() {
            return Enabled;
        }

        public void setEnabled(boolean Enabled) {
            this.Enabled = Enabled;
        }

        public int getAge() {
            return Age;
        }

        public void setAge(int Age) {
            this.Age = Age;
        }

        public String getName() {
            return Name;
        }

        public void setName(String Name) {
            this.Name = Name;
        }
    }

    public static void testEnforce(Enforcer e, Object sub, Object obj, String act, boolean res) {
        try {
            boolean myRes = e.enforce(sub, obj, act);
            assertEquals(Boolean.valueOf(myRes), Boolean.valueOf(res), String.format("%s, %s, %s: %b, supposed to be %b", sub, obj, act, myRes, res));
        } catch (Exception ex) {
            throw new RuntimeException(String.format("Enforce Error: %s", ex.getMessage()), ex);
        }
    }

    @Test
    public void testABACTypes(){
        Enforcer e = new Enforcer("examples/abac_model.conf");
        String matcher = "\"moderator\" in r.sub.Roles && r.sub.Enabled == true && r.sub.Age >= 21 && r.sub.Name != \"foo\"";
        e.getModel().model.get("m").get("m").value = (Util.removeComments(Util.escapeAssertion(matcher)));

        // Struct request
        StructRequest structRequest = new StructRequest();
        structRequest.setRoles(Arrays.asList("user", "moderator"));
        structRequest.setEnabled(true);
        structRequest.setAge(30);
        structRequest.setName("alice");
        testEnforce(e, structRequest, null, "", true);

        // Map request
        Map<String, Object> mapRequest = new HashMap<>();
        mapRequest.put("Roles", Arrays.asList("user", "moderator"));
        mapRequest.put("Enabled", true);
        mapRequest.put("Age", 30);
        mapRequest.put("Name", "alice");
        testEnforce(e, mapRequest, null, "", true);

        // JSON request
        e.enableAcceptJsonRequest(true);
        try {
            String jsonRequest = new ObjectMapper().writeValueAsString(mapRequest);
            testEnforce(e, jsonRequest, "", "", true);
        } catch (JsonProcessingException jsonProcessingException) {
            jsonProcessingException.printStackTrace();
        }
    }

    @Test
    public void testABACJsonRequest(){
        Enforcer e1 = new Enforcer("examples/abac_model.conf");
        e1.enableAcceptJsonRequest(true);

        Map data1Json = new HashMap<String,String>();
        data1Json.put("Name", "data1");
        data1Json.put("Owner", "alice");
        Map data2Json = new HashMap<String,String>();
        data2Json.put("Name", "data2");
        data2Json.put("Owner", "bob");

        testEnforce(e1, "alice", data1Json, "read", true);
        testEnforce(e1, "alice", data1Json, "write", true);
        testEnforce(e1, "alice", data2Json, "read", false);
        testEnforce(e1, "alice", data2Json, "write", false);
        testEnforce(e1, "bob", data1Json, "read", false);
        testEnforce(e1, "bob", data1Json, "write", false);
        testEnforce(e1, "bob", data2Json, "read", true);
        testEnforce(e1, "bob", data2Json, "write", true);


        Enforcer e2 = new Enforcer("examples/abac_not_using_policy_model.conf", "examples/abac_rule_effect_policy.csv");
        e2.enableAcceptJsonRequest(true);

        testEnforce(e2, "alice", data1Json, "read", true);
        testEnforce(e2, "alice", data1Json, "write", true);
        testEnforce(e2, "alice", data2Json, "read", false);
        testEnforce(e2, "alice", data2Json, "write", false);


        Enforcer e3 = new Enforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv");
        e3.enableAcceptJsonRequest(true);

        Map sub1Json = new HashMap<String,Object>();
        sub1Json.put("Name", "alice");
        sub1Json.put("Age", 16);
        Map sub2Json = new HashMap<String,String>();
        sub2Json.put("Name", "alice");
        sub2Json.put("Age", 20);
        Map sub3Json = new HashMap<String,String>();
        sub3Json.put("Name", "alice");
        sub3Json.put("Age", 65);

        testEnforce(e3, sub1Json, "/data1", "read", false);
        testEnforce(e3, sub1Json, "/data2", "read", false);
        testEnforce(e3, sub1Json, "/data1", "write", false);
        testEnforce(e3, sub1Json, "/data2", "write", true);
        testEnforce(e3, sub2Json, "/data1", "read", true);
        testEnforce(e3, sub2Json, "/data2", "read", false);
        testEnforce(e3, sub2Json, "/data1", "write", false);
        testEnforce(e3, sub2Json, "/data2", "write", true);
        testEnforce(e3, sub3Json, "/data1", "read", true);
        testEnforce(e3, sub3Json, "/data2", "read", false);
        testEnforce(e3, sub3Json, "/data1", "write", false);
        testEnforce(e3, sub3Json, "/data2", "write", false);
    }

    @Test
    public void testKeyMatchModel() {
        Enforcer e = new Enforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv");

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
    public void testKeyMatch2Model() {
        Enforcer e = new Enforcer("examples/keymatch2_model.conf", "examples/keymatch2_policy.csv");

        testEnforce(e, "alice", "/alice_data", "GET", false);
        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        testEnforce(e, "alice", "/alice_data2/myid", "GET", false);
        testEnforce(e, "alice", "/alice_data2/myid/using/res_id", "GET", true);
    }

    public boolean customFunction(String key1, String key2){
        if (key1.equals("/alice_data2/myid/using/res_id") && key2.equals("/alice_data/:resource")){
            return true;
        } else if (key1.equals("/alice_data2/myid/using/res_id") && key2.equals("/alice_data2/:id/using/:resId")){
            return true;
        } else {
            return false;
        }
    }

    public class customFunctionWrapper extends CustomFunction {
        @Override
        public AviatorObject call(Map<String, Object> env, AviatorObject arg1, AviatorObject arg2) {
            String key1 = FunctionUtils.getStringValue(arg1, env);
            String key2 = FunctionUtils.getStringValue(arg2, env);

            return AviatorBoolean.valueOf(customFunction(key1, key2));
        }

        @Override
        public String getName() {
            return "keyMatchCustom";
        }
    }

    @Test
    public void testKeyMatchCustomModel(){
        Enforcer e = new Enforcer("examples/keymatch_custom_model.conf", "examples/keymatch2_policy.csv");

        e.addFunction("keyMatchCustom", new customFunctionWrapper());

        testEnforce(e, "alice", "/alice_data2/myid", "GET", false);
        testEnforce(e, "alice", "/alice_data2/myid/using/res_id", "GET", true);
    }

    @Test
    public void testIPMatchModel() {
        Enforcer e = new Enforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv");

        testEnforce(e, "192.168.2.123", "data1", "read", true);
        testEnforce(e, "192.168.2.123", "data1", "write", false);
        testEnforce(e, "192.168.2.123", "data2", "read", false);
        testEnforce(e, "192.168.2.123", "data2", "write", false);

        testEnforce(e, "192.168.0.123", "data1", "read", false);
        testEnforce(e, "192.168.0.123", "data1", "write", false);
        testEnforce(e, "192.168.0.123", "data2", "read", false);
        testEnforce(e, "192.168.0.123", "data2", "write", false);

        testEnforce(e, "10.0.0.5", "data1", "read", false);
        testEnforce(e, "10.0.0.5", "data1", "write", false);
        testEnforce(e, "10.0.0.5", "data2", "read", false);
        testEnforce(e, "10.0.0.5", "data2", "write", true);

        testEnforce(e, "192.168.0.1", "data1", "read", false);
        testEnforce(e, "192.168.0.1", "data1", "write", false);
        testEnforce(e, "192.168.0.1", "data2", "read", false);
        testEnforce(e, "192.168.0.1", "data2", "write", false);
    }

    @Test
    public void testPriorityModel() {
        Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", false);
    }

    @Test
    public void testPriorityHierachyModel(){
        Enforcer e = new Enforcer("examples/priority_hierachy_policy.conf", "examples/priority_hierachy_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "jane", "data1", "read", true);
    }

    @Test
    public void testPriorityModelIndeterminate() {
        Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_indeterminate_policy.csv");

        testEnforce(e, "alice", "data1", "read", false);
    }

    @Test
    public void testRBACModelInMultiLines(){
        Enforcer e = new Enforcer("examples/rbac_model_in_multi_line.conf", "examples/rbac_policy.csv");

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
    public void testABACNotUsingPolicy(){
        Enforcer e = new Enforcer("examples/abac_not_using_policy_model.conf", "examples/abac_rule_effect_policy.csv");

        TestResource data1 = new TestResource("data1", "alice");
        TestResource data2 = new TestResource("data2", "bob");

        testEnforce(e, "alice", data1, "read", true);
        testEnforce(e, "alice", data1, "write", true);
        testEnforce(e, "alice", data2, "read", false);
        testEnforce(e, "alice", data2, "write", false);
    }

    public class TestSubject{
        private String name;
        private int age;

        public TestSubject(String name, int age){
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }

    @Test
    public void testABACPolicy(){
        Enforcer e = new Enforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv");

        TestSubject sub1 = new TestSubject("alice", 16);
        TestSubject sub2 = new TestSubject("alice", 20);
        TestSubject sub3 = new TestSubject("alice", 65);

        testEnforce(e, sub1, "/data1", "read", false);
        testEnforce(e, sub1, "/data2", "read", false);
        testEnforce(e, sub1, "/data1", "write", false);
        testEnforce(e, sub1, "/data2", "write", true);
        testEnforce(e, sub2, "/data1", "read", true);
        testEnforce(e, sub2, "/data2", "read", false);
        testEnforce(e, sub2, "/data1", "write", false);
        testEnforce(e, sub2, "/data2", "write", true);
        testEnforce(e, sub3, "/data1", "read", true);
        testEnforce(e, sub3, "/data2", "read", false);
        testEnforce(e, sub3, "/data1", "write", false);
        testEnforce(e, sub3, "/data2", "write", false);
    }

    @Test
    public void testCommentModel(){
        Enforcer e = new Enforcer("examples/comment_model.conf", "examples/basic_policy.csv");

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
    public void testDomainMatchModel(){
        Enforcer e = new Enforcer("examples/rbac_with_domain_pattern_model.conf", "examples/rbac_with_domain_pattern_policy.csv");
        e.addNamedDomainMatchingFunc("g", "keyMatch2", BuiltInFunctions::keyMatch2);

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "alice", "domain2", "data2", "read", true);
        testDomainEnforce(e, "alice", "domain2", "data2", "write", true);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testAllMatchModel(){
        Enforcer e = new Enforcer("examples/rbac_with_all_pattern_model.conf", "examples/rbac_with_all_pattern_policy.csv");
        e.addNamedMatchingFunc("g", "keyMatch2", BuiltInFunctions::keyMatch2);
        e.addNamedDomainMatchingFunc("g", "keyMatch2", BuiltInFunctions::keyMatch2);

        testDomainEnforce(e, "alice", "domain1", "/book/1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "/book/1", "write", false);
        testDomainEnforce(e, "alice", "domain2", "/book/1", "read", false);
        testDomainEnforce(e, "alice", "domain2", "/book/1", "write", true);
    }

    @Test
    public void testSubjectPriorityWithDomain() {
        Enforcer e = new Enforcer("examples/subject_priority_model_with_domain.conf", "examples/subject_priority_policy_with_domain.csv");

        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testGlobMatchModel() {
        Enforcer e = new Enforcer("examples/glob_model.conf", "examples/glob_policy.csv");

        testEnforce(e, "u1", "/foo/", "read", true);
        testEnforce(e, "u1", "/foo", "read", false);
        testEnforce(e, "u1", "/foo/subprefix", "read", true);
        testEnforce(e, "u1", "foo", "read", false);

        testEnforce(e, "u2", "/foosubprefix", "read", true);
        testEnforce(e, "u2", "/foo/subprefix", "read", false);
        testEnforce(e, "u2", "foo", "read", false);

        testEnforce(e, "u3", "/prefix/foo/subprefix", "read", true);
        testEnforce(e, "u3", "/prefix/foo/", "read", true);
        testEnforce(e, "u3", "/prefix/foo", "read", false);

        testEnforce(e, "u4", "/foo", "read", false);
        testEnforce(e, "u4", "foo", "read", true);
    }

    @Test
    public void testRbacWithResourceRolesAndDomain() {
        Enforcer e = new Enforcer("examples/rbac_with_resource_roles_and_domain_model.conf", "examples/rbac_with_resource_roles_and_domain_policy.csv");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "alice", "domain2", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain2", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain2", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain2", "data2", "write", false);

        testDomainEnforce(e, "bob", "domain1", "data2", "read", false);
        testDomainEnforce(e, "bob", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain1", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain1", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testTemporalRolesModel(){
        Enforcer e = new Enforcer("examples/rbac_with_temporal_roles_model.conf", "examples/rbac_with_temporal_roles_policy.csv");

        e.addNamedLinkConditionFunc("g", "alice", "data2_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data3_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data4_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data5_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data6_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data7_admin", BuiltInFunctions::timeMatchFunc);
        e.addNamedLinkConditionFunc("g", "alice", "data8_admin", BuiltInFunctions::timeMatchFunc);

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "alice", "data3", "read", true);
        testEnforce(e, "alice", "data3", "write", true);
        testEnforce(e, "alice", "data4", "read", true);
        testEnforce(e, "alice", "data4", "write", true);
        testEnforce(e, "alice", "data5", "read", true);
        testEnforce(e, "alice", "data5", "write", true);
        testEnforce(e, "alice", "data6", "read", false);
        testEnforce(e, "alice", "data6", "write", false);
        testEnforce(e, "alice", "data7", "read", true);
        testEnforce(e, "alice", "data7", "write", true);
        testEnforce(e, "alice", "data8", "read", false);
        testEnforce(e, "alice", "data8", "write", false);
    }

    @Test
    public void testTemporalRolesModelWithDomain(){
        Enforcer e = new Enforcer("examples/rbac_with_domain_temporal_roles_model.conf", "examples/rbac_with_domain_temporal_roles_policy.csv");

        e.addNamedDomainLinkConditionFunc("g", "alice", "data2_admin", "domain2", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data3_admin", "domain3", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data4_admin", "domain4", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data5_admin", "domain5", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data6_admin", "domain6", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data7_admin", "domain7", BuiltInFunctions::timeMatchFunc);
        e.addNamedDomainLinkConditionFunc("g", "alice", "data8_admin", "domain8", BuiltInFunctions::timeMatchFunc);

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain2", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain2", "data2", "write", false);
        testDomainEnforce(e, "alice", "domain3", "data3", "read", true);
        testDomainEnforce(e, "alice", "domain3", "data3", "write", true);
        testDomainEnforce(e, "alice", "domain4", "data4", "read", true);
        testDomainEnforce(e, "alice", "domain4", "data4", "write", true);
        testDomainEnforce(e, "alice", "domain5", "data5", "read", true);
        testDomainEnforce(e, "alice", "domain5", "data5", "write", true);
        testDomainEnforce(e, "alice", "domain6", "data6", "read", false);
        testDomainEnforce(e, "alice", "domain6", "data6", "write", false);
        testDomainEnforce(e, "alice", "domain7", "data7", "read", true);
        testDomainEnforce(e, "alice", "domain7", "data7", "write", true);
        testDomainEnforce(e, "alice", "domain8", "data8", "read", false);
        testDomainEnforce(e, "alice", "domain8", "data8", "write", false);

        testDomainEnforce(e, "alice", "domain_not_exist", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data2", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data3", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data3", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data4", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data4", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data5", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data5", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data6", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data6", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data7", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data7", "write", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data8", "read", false);
        testDomainEnforce(e, "alice", "domain_not_exist", "data8", "write", false);
    }
}
