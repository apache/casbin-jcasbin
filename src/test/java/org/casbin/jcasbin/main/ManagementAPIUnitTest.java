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
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.*;
import static org.testng.Assert.assertEquals;

public class ManagementAPIUnitTest {
    @Test
    public void testGetPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetPolicy(e, asList(
            asList("alice", "data1", "read"),
            asList("bob", "data2", "write"),
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write")));

        testGetFilteredPolicy(e, 0, asList(asList("alice", "data1", "read")), "alice");
        testGetFilteredPolicy(e, 0, asList(asList("bob", "data2", "write")), "bob");
        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2_admin");
        testGetFilteredPolicy(e, 1, asList(asList("alice", "data1", "read")), "data1");
        testGetFilteredPolicy(e, 1, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2");
        testGetFilteredPolicy(e, 2, asList(asList("alice", "data1", "read"), asList("data2_admin", "data2", "read")), "read");
        testGetFilteredPolicy(e, 2, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "write")), "write");

        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2_admin", "data2");
        // Note: "" (empty string) in fieldValues means matching all values.
        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read")), "data2_admin", "", "read");
        testGetFilteredPolicy(e, 1, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "write")), "data2", "write");

        testHasPolicy(e, asList("alice", "data1", "read"), true);
        testHasPolicy(e, asList("bob", "data2", "write"), true);
        testHasPolicy(e, asList("alice", "data2", "read"), false);
        testHasPolicy(e, asList("bob", "data3", "write"), false);

        testGetGroupingPolicy(e, asList(asList("alice", "data2_admin")));

        testGetFilteredGroupingPolicy(e, 0, asList(asList("alice", "data2_admin")), "alice");
        testGetFilteredGroupingPolicy(e, 0, asList(), "bob");
        testGetFilteredGroupingPolicy(e, 1, asList(), "data1_admin");
        testGetFilteredGroupingPolicy(e, 1, asList(asList("alice", "data2_admin")), "data2_admin");
        // Note: "" (empty string) in fieldValues means matching all values.
        testGetFilteredGroupingPolicy(e, 0, asList(asList("alice", "data2_admin")), "", "data2_admin");

        testHasGroupingPolicy(e, asList("alice", "data2_admin"), true);
        testHasGroupingPolicy(e, asList("bob", "data2_admin"), false);
    }

    @Test
    public void testModifyPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetPolicy(e, asList(
            asList("alice", "data1", "read"),
            asList("bob", "data2", "write"),
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write")));

        e.removePolicy("alice", "data1", "read");
        e.removePolicy("bob", "data2", "write");
        e.removePolicy("alice", "data1", "read");
        e.addPolicy("eve", "data3", "read");
        e.addPolicy("eve", "data3", "read");

        String[][] rules = {
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"katy", "data4", "write"},
            {"leyo", "data4", "read"},
            {"katy", "data4", "write"},
            {"katy", "data4", "write"},
            {"ham", "data4", "write"},
        };

        e.addPolicies(rules);
        e.addPolicies(rules);

        testGetPolicy(e, asList(
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write"),
            asList("eve", "data3", "read"),
            asList("jack", "data4", "read"),
            asList("katy", "data4", "write"),
            asList("leyo", "data4", "read"),
            asList("ham", "data4", "write")));

        e.removePolicies(rules);
        e.removePolicies(rules);

        List<String> namedPolicy = asList("eve", "data3", "read");
        e.removeNamedPolicy("p", namedPolicy);
        e.addNamedPolicy("p", namedPolicy);

        testGetPolicy(e, asList(
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write"),
            asList("eve", "data3", "read")));

        e.removeFilteredPolicy(1, "data2");

        testGetPolicy(e, asList(asList("eve", "data3", "read")));

        e.updatePolicy(asList("eve", "data3", "read"), asList("eve", "data2", "read"));
        testGetPolicy(e, asList(asList("eve", "data2", "read")));

        e.updateNamedPolicy("p", asList("eve", "data2", "read"), asList("eve", "data4", "read"));
        testGetPolicy(e, asList(asList("eve", "data4", "read")));

        e.addNamedPolicies("p", asList(asList("eve", "data4", "read"), asList("user1", "data1", "read")));
        testGetPolicy(e, asList(asList("eve", "data4", "read")));

        e.addNamedPoliciesEx("p", asList(asList("eve", "data4", "read"), asList("user1", "data1", "read")));
        testGetPolicy(e, asList(asList("eve", "data4", "read"), asList("user1", "data1", "read")));



    }

    @Test
    public void testModifyGroupingPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList());
        testGetRoles(e, "non_exist", asList());

        e.removeGroupingPolicy("alice", "data2_admin");
        e.addGroupingPolicy("bob", "data1_admin");
        e.addGroupingPolicy("eve", "data3_admin");

        String[][] groupingRules = {
            {"ham", "data4_admin"},
            {"jack", "data5_admin"}
        };

        e.addGroupingPolicies(groupingRules);
        testGetRoles(e, "ham", asList("data4_admin"));
        testGetRoles(e, "jack", asList("data5_admin"));
        e.removeGroupingPolicies(groupingRules);

        List<String> namedGroupingPolicy = asList("alice", "data2_admin");
        testGetRoles(e, "alice", asList());
        e.addNamedGroupingPolicy("g", namedGroupingPolicy);
        testGetRoles(e, "alice", asList("data2_admin"));
        e.removeNamedGroupingPolicy("g", namedGroupingPolicy);

        e.addNamedGroupingPolicies("g", groupingRules);
        e.addNamedGroupingPolicies("g", groupingRules);
        testGetRoles(e, "ham", asList("data4_admin"));
        testGetRoles(e, "jack", asList("data5_admin"));
        e.removeNamedGroupingPolicies("g", groupingRules);
        e.removeNamedGroupingPolicies("g", groupingRules);

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList("bob"));
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));

        e.removeFilteredGroupingPolicy(0, "bob");

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));

        e.updateGroupingPolicy(asList("eve", "data3_admin"), asList("eve", "data3_admin_update"));

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin_update"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin_update", asList("eve"));

        e.updateNamedGroupingPolicy("g", asList("eve", "data3_admin_update"), asList("eve", "data3_admin"));

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));
    }

    @Test
    public void testModifyGroupingPolicyAPIEx() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        // Initial state: alice has role data2_admin
        testGetRoles(e, "alice", asList("data2_admin"));

        String[][] groupingRules = {
            {"alice", "data2_admin"}, // This rule already exists
            {"bob", "data1_admin"},   // This is new
            {"eve", "data3_admin"}    // This is new
        };

        // Test addGroupingPoliciesEx - should add only new rules (bob and eve), not fail on existing (alice)
        boolean result = e.addGroupingPoliciesEx(groupingRules);
        Assert.assertTrue(result, "addGroupingPoliciesEx should return true");
        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "eve", asList("data3_admin"));

        // Clean up for next test
        e.removeGroupingPolicy("bob", "data1_admin");
        e.removeGroupingPolicy("eve", "data3_admin");

        // Test with List<List<String>>
        List<List<String>> groupingRulesList = asList(
            asList("alice", "data2_admin"), // Already exists
            asList("bob", "data1_admin"),   // New
            asList("ham", "data4_admin")    // New
        );

        result = e.addGroupingPoliciesEx(groupingRulesList);
        Assert.assertTrue(result, "addGroupingPoliciesEx with List should return true");
        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "ham", asList("data4_admin"));

        // Clean up
        e.removeGroupingPolicy("bob", "data1_admin");
        e.removeGroupingPolicy("ham", "data4_admin");

        // Test addNamedGroupingPoliciesEx with List<List<String>>
        result = e.addNamedGroupingPoliciesEx("g", groupingRulesList);
        Assert.assertTrue(result, "addNamedGroupingPoliciesEx with List should return true");
        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "ham", asList("data4_admin"));

        // Clean up
        e.removeGroupingPolicy("bob", "data1_admin");
        e.removeGroupingPolicy("ham", "data4_admin");

        // Test addNamedGroupingPoliciesEx with String[][]
        result = e.addNamedGroupingPoliciesEx("g", groupingRules);
        Assert.assertTrue(result, "addNamedGroupingPoliciesEx with String[][] should return true");
        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "eve", asList("data3_admin"));
    }

    @Test
    public void testGetAllUsers() {
        // Basic RBAC: alice and bob are users, data2_admin is a role
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        assertUserSet(e.getAllSubjects(), asList("alice", "bob", "data2_admin"));
        assertUserSet(e.getAllRoles(), asList("data2_admin"));
        assertUserSet(e.getAllUsers(), asList("alice", "bob"));

        // Add a regular user who only appears in policy, not as a role target
        e.addPolicy("eve", "data3", "read");
        assertUserSet(e.getAllUsers(), asList("alice", "bob", "eve"));
        e.removePolicy("eve", "data3", "read");

        // A subject who is also a role target: admin is in p AND assigned to role "root" via g
        // getAllUsers = subjects(p) - roles(g col 1); admin is not in g col 1, so it is a user
        e.addPolicy("admin", "data1", "read");
        e.addGroupingPolicy("admin", "root");
        assertUserSet(e.getAllUsers(), asList("alice", "bob", "admin"));
        e.removePolicy("admin", "data1", "read");
        e.removeGroupingPolicy("admin", "root");

        // After clearing all policies, everything should be empty
        e.clearPolicy();
        assertUserSet(e.getAllSubjects(), asList());
        assertUserSet(e.getAllRoles(), asList());
        assertUserSet(e.getAllUsers(), asList());
    }

    private void assertUserSet(List<String> actual, List<String> expected) {
        if (!Util.setEquals(expected, actual)) {
            Assert.fail("Expected: " + expected + ", got: " + actual);
        }
    }

}
