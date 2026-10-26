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

import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.ConditionalRoleManager;
import org.casbin.jcasbin.rbac.ConditionalDomainManager;
import org.casbin.jcasbin.rbac.DomainManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.testng.Assert.assertEquals;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
public class RoleManagerUnitTest {
    @Test
    public void testMatchingPreservesConditionsRegisteredBeforeLinks() {
        ConditionalRoleManager rm = new ConditionalRoleManager(10);
        rm.addLinkConditionFunc("alice", "admin", params -> "allow".equals(params[0]));
        rm.setLinkConditionFuncParams("alice", "admin", "deny");
        rm.addMatchingFunc("keyMatch", BuiltInFunctions::keyMatch);
        rm.addLink("alice", "admin");
        TestUtil.testHasRole(rm, "alice", "admin", false);

        rm.setLinkConditionFuncParams("alice", "admin", "allow");
        TestUtil.testHasRole(rm, "alice", "admin", true);
        rm.addMatchingFunc("exact", String::equals);
        rm.setLinkConditionFuncParams("alice", "admin", "deny");
        TestUtil.testHasRole(rm, "alice", "admin", false);
    }

    @Test
    public void testDeletingPatternLinkPreservesExplicitDomainLink() {
        DomainManager standard = new DomainManager(10);
        standard.addDomainMatchingFunc("keyMatch", BuiltInFunctions::keyMatch);
        ConditionalDomainManager conditional = new ConditionalDomainManager(10);
        conditional.addDomainMatchingFunc("keyMatch", BuiltInFunctions::keyMatch);
        for (RoleManager rm : Arrays.asList(standard, conditional)) {
            rm.addLink("alice", "admin", "tenant*");
            rm.addLink("alice", "admin", "tenantA");
            TestUtil.testHasRole(rm, "alice", "admin", "tenantA", true);
            TestUtil.testHasRole(rm, "alice", "admin", "tenantB", true);

            rm.deleteLink("alice", "admin", "tenant*");
            TestUtil.testHasRole(rm, "alice", "admin", "tenantA", true);
            TestUtil.testHasRole(rm, "alice", "admin", "tenantB", false);
            TestUtil.testGetRoles(rm, "alice", "tenantA", Collections.singletonList("admin"));
            assertEquals(rm.getUsers("admin", "tenantA"), Collections.singletonList("alice"));

            rm.clear();
            TestUtil.testHasRole(rm, "alice", "admin", "tenantA", false);
        }
    }

    @Test
    public void testDomainConditionsRegisteredBeforePatternLinks() {
        ConditionalDomainManager rm = new ConditionalDomainManager(10);
        rm.addDomainMatchingFunc("keyMatch", BuiltInFunctions::keyMatch);
        rm.addDomainLinkConditionFunc("alice", "admin", "tenantA", params -> "allow".equals(params[0]));
        rm.setDomainLinkConditionFuncParams("alice", "admin", "tenantA", "deny");
        rm.addLink("alice", "admin", "tenant*");
        TestUtil.testHasRole(rm, "alice", "admin", "tenantA", false);

        rm.setDomainLinkConditionFuncParams("alice", "admin", "tenantA", "allow");
        TestUtil.testHasRole(rm, "alice", "admin", "tenantA", true);
        rm.addDomainLinkConditionFunc("alice", "admin", "tenantA", params -> false);
        TestUtil.testHasRole(rm, "alice", "admin", "tenantA", false);
    }

    @Test
    public void testRole() {
        RoleManager rm = new DefaultRoleManager(3);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("u3", "g2");
        rm.addLink("u4", "g2");
        rm.addLink("u4", "g3");
        rm.addLink("g1", "g3");

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", true);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", true);
        TestUtil.testHasRole(rm, "u2", "g1", true);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", true);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", true);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", true);
        TestUtil.testHasRole(rm, "u4", "g3", true);

        TestUtil.testGetRoles(rm, "u1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u2", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u3", Collections.singletonList("g2"));
        TestUtil.testGetRoles(rm, "u4", Arrays.asList("g2", "g3"));
        TestUtil.testGetRoles(rm, "g1", Collections.singletonList("g3"));
        TestUtil.testGetRoles(rm, "g2", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g3", Collections.emptyList());

        rm.deleteLink("g1", "g3");
        rm.deleteLink("u4", "g2");

        // Current role inheritance tree after deleting the links:
        //             g3    g2
        //               \     \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", true);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", false);
        TestUtil.testHasRole(rm, "u2", "g1", true);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", false);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", true);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", false);
        TestUtil.testHasRole(rm, "u4", "g3", true);

        TestUtil.testGetRoles(rm, "u1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u2", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u3", Collections.singletonList("g2"));
        TestUtil.testGetRoles(rm, "u4", Collections.singletonList("g3"));
        TestUtil.testGetRoles(rm, "g1", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g2", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g3", Collections.emptyList());
    }

    @Test
    public void testDomainRole() {
        RoleManager rm = new DomainManager(3);
        rm.addLink("u1", "g1", "domain1");
        rm.addLink("u2", "g1", "domain1");
        rm.addLink("u3", "admin", "domain2");
        rm.addLink("u4", "admin", "domain2");
        rm.addLink("u4", "admin", "domain1");
        rm.addLink("g1", "admin", "domain1");

        //  Current role inheritance tree:
        //  domain1:admin    domain2:admin
        //      /       \  /       \
        //  domain1:g1     u4         u3
        //      /  \
        //  u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u2", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u3", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain2", true);

        TestUtil.testHasRole(rm, "u4", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u4", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u4", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u4", "admin", "domain2", true);

        rm.deleteLink("g1", "admin", "domain1");
        rm.deleteLink("u4", "admin", "domain2");

        // Current role inheritance tree after deleting the links:
        //       domain1:admin    domain2:admin
        //                    \          \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u2", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u3", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain2", true);

        TestUtil.testHasRole(rm, "u4", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u4", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u4", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u4", "admin", "domain2", false);
    }

    @Test
    public void testClear() {
        RoleManager rm = new DefaultRoleManager(3);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("u3", "g2");
        rm.addLink("u4", "g2");
        rm.addLink("u4", "g3");
        rm.addLink("g1", "g3");

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        rm.clear();

        // All data is cleared.
        // No role inheritance now.

        TestUtil.testHasRole(rm, "u1", "g1", false);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", false);
        TestUtil.testHasRole(rm, "u2", "g1", false);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", false);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", false);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", false);
        TestUtil.testHasRole(rm, "u4", "g3", false);
    }

    @Test
    public void testDomainPatternRole() {
        DomainManager rm = new DomainManager(10);
        rm.addDomainMatchingFunc("allMatch", BuiltInFunctions::allMatch);

        rm.addLink("u1", "g1", "domain1");
        rm.addLink("u2", "g1", "domain2");
        rm.addLink("u3", "g1", "*");
        rm.addLink("u4", "g2", "domain3");

        // Current role inheritance tree after deleting the links:
        //       domain1:g1    domain2:g1			domain3:g2
        //		   /      \    /      \					|
        //	 domain1:u1    *:g1     domain2:u2		domain3:u4
        // 					|
        // 				   *:u3

        TestUtil.testHasRole(rm, "u1", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u2", "g1", "domain2", true);
        TestUtil.testHasRole(rm, "u3", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u3", "g1", "domain2", true);
        TestUtil.testHasRole(rm, "u1", "g2", "domain1", false);
        TestUtil.testHasRole(rm, "u4", "g2", "domain3", true);
        TestUtil.testHasRole(rm, "u3", "g2", "domain3", false);

        TestUtil.testGetRoles(rm, "u3", "domain1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u1", "domain1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u3", "domain2", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u1", "domain2", Collections.emptyList());
        TestUtil.testGetRoles(rm, "u4", "domain3", Collections.singletonList("g2"));
    }

    @Test
    public void testAllMatchingFunc() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.addMatchingFunc("keyMatch2", BuiltInFunctions::keyMatch2);
        rm.addDomainMatchingFunc("allMatch", BuiltInFunctions::allMatch);

        rm.addLink("/book/:id", "book_group", "*");

        TestUtil.testHasRole(rm, "/book/1", "book_group", "domain1", true);
        TestUtil.testHasRole(rm, "/book/2", "book_group", "domain1", true);
    }

    @Test
    public void testMatchingFuncOrder() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.addMatchingFunc("regexMatch", BuiltInFunctions::regexMatch);

        rm.addLink("u1", "g\\d+");
        TestUtil.testHasRole(rm, "u1", "g1", true);
        TestUtil.testHasRole(rm, "u1", "g2", true);

        rm.clear();

        rm.addLink("g\\d+", "root");
        rm.addLink("u1", "g1");
        TestUtil.testHasRole(rm, "u1", "root", true);

        rm.clear();

        rm.addLink("u1", "g1");
        rm.addLink("g\\d+", "root");
        TestUtil.testHasRole(rm, "u1", "root", true);
    }

    @Test
    public void testDomainMatchingFuncWithDifferentDomain() {
        DomainManager rm = new DomainManager(10);
        rm.addDomainMatchingFunc("keyMatch", BuiltInFunctions::keyMatch);

        rm.addLink("alice", "editor", "*");
        rm.addLink("editor", "admin", "domain1");

        TestUtil.testHasRole(rm, "alice", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "alice", "admin", "domain2", false);
    }

    @Test
    public void testTemporaryRoles() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.addMatchingFunc("regexMatch", BuiltInFunctions::regexMatch);

        rm.addLink("u\\d+", "user");

        for (int i = 0; i < 10; i++) {
            TestUtil.testHasRole(rm, "u" + i, "user", true);
        }

        TestUtil.testGetUsers(rm, "user", Collections.singletonList("u\\d+"));
        TestUtil.testGetRoles(rm, "u1", Collections.singletonList("user"));

        rm.addLink("u1", "manager");

        for (int i = 10; i < 20; i++) {
            TestUtil.testHasRole(rm, "u" + i, "user", true);
        }

        TestUtil.testGetUsers(rm, "user", Arrays.asList("u\\d+", "u1"));
        TestUtil.testGetRoles(rm, "u1", Arrays.asList("user", "manager"));
    }

    @Test
    public void testMaxHierarchyLevel() {
        DefaultRoleManager rm = new DefaultRoleManager(1);
        rm.addLink("level0", "level1");
        rm.addLink("level1", "level2");
        rm.addLink("level2", "level3");

        TestUtil.testHasRole(rm, "level0", "level0", true);
        TestUtil.testHasRole(rm, "level0", "level1", true);
        TestUtil.testHasRole(rm, "level0", "level2", false);
        TestUtil.testHasRole(rm, "level0", "level3", false);
        TestUtil.testHasRole(rm, "level1", "level2", true);
        TestUtil.testHasRole(rm, "level1", "level3", false);

        rm = new DefaultRoleManager(2);
        rm.addLink("level0", "level1");
        rm.addLink("level1", "level2");
        rm.addLink("level2", "level3");

        TestUtil.testHasRole(rm, "level0", "level0", true);
        TestUtil.testHasRole(rm, "level0", "level1", true);
        TestUtil.testHasRole(rm, "level0", "level2", true);
        TestUtil.testHasRole(rm, "level0", "level3", false);
        TestUtil.testHasRole(rm, "level1", "level2", true);
        TestUtil.testHasRole(rm, "level1", "level3", true);
    }
}
