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

import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.DomainManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.testng.annotations.Test;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.*;

public class RbacAPIWithPatternMatchUnitTest {

    @Test
    public void testInvalidPatternInGroupingPolicy() {
        Enforcer e = new Enforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv");
        e.enableAutoSave(false);
        e.addNamedMatchingFunc("g2", "keyMatch2", BuiltInFunctions::keyMatch2);
        e.addNamedGroupingPolicy("g2", "/book/(1", "book_group");

        testEnforce(e, "alice", "/book/1", "GET", true);
        testEnforce(e, "alice", "/book/(1", "GET", true);
        testEnforce(e, "alice", "/pen/1", "GET", true);
        testEnforce(e, "alice", "/pen/2", "GET", false);
    }

    @Test
    public void testEnforceAPIWithKeyMatch3Pattern() {
        final Enforcer e = new Enforcer("examples/rbac_with_pattern_model.conf");
        e.setAdapter(new FileAdapter("examples/rbac_with_pattern_policy.csv"));
        e.setRoleManager("g2", new DefaultRoleManager(10, BuiltInFunctions::keyMatch3, null));
        e.loadPolicy();

        testEnforce(e, "alice", "/book/1", "GET", true);
        testEnforce(e, "alice", "/book/2", "GET", true);
        testEnforce(e, "alice", "/pen/1", "GET", true);
        testEnforce(e, "alice", "/pen/2", "GET", false);
        testEnforce(e, "bob", "/book/1", "GET", false);
        testEnforce(e, "bob", "/book/2", "GET", false);
        testEnforce(e, "bob", "/pen/1", "GET", false);
        testEnforce(e, "bob", "/pen/2", "GET", false);

        testEnforce(e, "alice", "/book2/1", "GET", true);
        testEnforce(e, "alice", "/book2/2", "GET", true);
        testEnforce(e, "alice", "/pen2/1", "GET", true);
        testEnforce(e, "alice", "/pen2/2", "GET", false);
        testEnforce(e, "bob", "/book2/1", "GET", false);
        testEnforce(e, "bob", "/book2/2", "GET", false);
        testEnforce(e, "bob", "/pen2/1", "GET", true);
        testEnforce(e, "bob", "/pen2/2", "GET", true);
    }

    @Test
    public void testEnforceAPIWithDomainMatch() {
        final Enforcer e = new Enforcer("examples/rbac_with_domain_pattern_model.conf");
        e.setAdapter(new FileAdapter("examples/rbac_with_domain_pattern_policy.csv"));
        e.setRoleManager(new DomainManager(10, null, BuiltInFunctions::allMatch));
        e.loadPolicy();

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
    public void testRoleAPIWithDomainMatch() {
        final Enforcer e = new Enforcer("examples/rbac_with_domain_pattern_model.conf");
        e.setAdapter(new FileAdapter("examples/rbac_with_domain_pattern_policy.csv"));
        e.setRoleManager(new DomainManager(10, null, BuiltInFunctions::allMatch));
        e.loadPolicy();

        testGetRolesInDomain(e, "alice", "domain1", asList("admin"));
        testGetRolesInDomain(e, "alice", "domain2", asList("admin"));

        testGetRolesInDomain(e, "bob", "domain1", asList());
        testGetRolesInDomain(e, "bob", "domain2", asList("admin"));
    }

    @Test
    public void testUserAPIWithDomainMatch() {
        final Enforcer e = new Enforcer("examples/rbac_with_domain_pattern_model.conf", "examples/rbac_with_domain_pattern_policy.csv");
        e.setRoleManager(new DomainManager(10, null, BuiltInFunctions::allMatch));
        e.loadPolicy();

        testGetUsersInDomain(e, "admin", "domain1", asList("alice"));
        testGetUsersInDomain(e, "admin", "domain2", asList("alice", "bob"));
        testGetUsersInDomain(e, "admin", "any_domain", asList("alice"));

        testGetUsersInDomain(e, "bob", "domain1", asList());
        testGetUsersInDomain(e, "alice", "domain2", asList());
    }

    @Test
    public void testImplicitPermissionAPIWithDomainMatch() {
        final Enforcer e = new Enforcer("examples/rbac_with_domain_pattern_model.conf");
        e.setAdapter(new FileAdapter("examples/rbac_with_domain_pattern_policy.csv"));
        e.setRoleManager(new DefaultRoleManager(10, null, BuiltInFunctions::allMatch));
        e.loadPolicy();

        testGetImplicitPermissionsInDomain(e, "alice", "domain1",
                asList(asList("admin", "domain1", "data1", "read"), asList("admin", "domain1", "data1", "write")));
    }

    @Test
    public void testEnforceAPIWithAllMatchPatterns() {
        final Enforcer e = new Enforcer("examples/rbac_with_all_pattern_model.conf", "examples/rbac_with_all_pattern_policy.csv");
        e.addNamedMatchingFunc("g", "KeyMatch2", BuiltInFunctions::keyMatch2);
        e.addNamedDomainMatchingFunc("g", "AllMatch", BuiltInFunctions::allMatch);

        testDomainEnforce(e, "alice", "domain1", "/book/1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "/book/1", "write", false);
        testDomainEnforce(e, "alice", "domain2", "/book/1", "read", false);
        testDomainEnforce(e, "alice", "domain2", "/book/1", "write", true);
    }
}
