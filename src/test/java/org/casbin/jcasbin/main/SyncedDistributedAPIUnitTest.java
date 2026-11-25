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

import org.testng.annotations.Test;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;

public class SyncedDistributedAPIUnitTest {

    @Test
    public void testDistributedAPI() {
        DistributedEnforcer de = new DistributedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        de.addPolicySelf(() -> false, "p", "p", asList(
            asList("alice", "data1", "read"),
            asList("bob", "data2", "write"),
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write")));
        de.addPolicySelf(() -> false, "g", "g", asList(
            asList("alice", "data2_admin"),
            asList("new_user", "data2_admin")
        ));

        testEnforce(de, "alice", "data1", "read", true);
        testEnforce(de, "alice", "data1", "write", false);
        testEnforce(de, "bob", "data2", "read", false);
        testEnforce(de, "bob", "data2", "write", true);
        testEnforce(de, "data2_admin", "data2", "read", true);
        testEnforce(de, "data2_admin", "data2", "write", true);
        testEnforce(de, "alice", "data2", "read", true);
        testEnforce(de, "alice", "data2", "write", true);
        testEnforce(de, "new_user", "data2", "write", true);
        testEnforce(de, "new_user", "data2", "read", true);

        de.updatePolicySelf(() -> false, "p", "p", asList("alice", "data1", "read"), asList("alice", "data1", "write"));
        de.updatePolicySelf(() -> false, "g", "g", asList("alice", "data2_admin"), asList("tom", "alice"));

        testEnforce(de, "alice", "data1", "read", false);
        testEnforce(de, "alice", "data1", "write", true);
        testEnforce(de, "bob", "data2", "read", false);
        testEnforce(de, "bob", "data2", "write", true);
        testEnforce(de, "data2_admin", "data2", "read", true);
        testEnforce(de, "data2_admin", "data2", "write", true);
        testEnforce(de, "tom", "data1", "read", false);
        testEnforce(de, "tom", "data1", "write", true);

        de.removePolicySelf(() -> false, "p", "p", asList(asList("alice", "data1", "write")));
        de.removePolicySelf(() -> false, "g", "g", asList(asList("alice", "data2_admin")));

        testEnforce(de, "alice", "data1", "read", false);
        testEnforce(de, "alice", "data1", "write", false);
        testEnforce(de, "bob", "data2", "read", false);
        testEnforce(de, "bob", "data2", "write", true);
        testEnforce(de, "data2_admin", "data2", "read", true);
        testEnforce(de, "data2_admin", "data2", "write", true);
        testEnforce(de, "alice", "data2", "read", false);
        testEnforce(de, "alice", "data2", "write", false);

        de.removeFilteredPolicySelf(() -> false, "p", "p", 0, "bob", "data2", "write");
        de.removeFilteredPolicySelf(() -> false, "g", "g", 0, "tom", "data2_admin");

        testEnforce(de, "alice", "data1", "read", false);
        testEnforce(de, "alice", "data1", "write", false);
        testEnforce(de, "bob", "data2", "read", false);
        testEnforce(de, "bob", "data2", "write", false);
        testEnforce(de, "data2_admin", "data2", "read", true);
        testEnforce(de, "data2_admin", "data2", "write", true);
        testEnforce(de, "tom", "data1", "read", false);
        testEnforce(de, "tom", "data1", "write", false);

        de.clearPolicySelf(() -> false);

        testEnforce(de, "alice", "data1", "read", false);
        testEnforce(de, "alice", "data1", "write", false);
        testEnforce(de, "bob", "data2", "read", false);
        testEnforce(de, "bob", "data2", "write", false);
        testEnforce(de, "data2_admin", "data2", "read", false);
        testEnforce(de, "data2_admin", "data2", "write", false);

        de.addPolicy("data2_admin", "data2", "read");
        testEnforce(de, "new_user", "data2", "read", false);
        testEnforce(de, "data2_admin", "data2", "read", true);
    }
}
