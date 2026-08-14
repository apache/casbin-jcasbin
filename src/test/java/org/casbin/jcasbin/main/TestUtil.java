// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.main;

import com.googlecode.aviator.AviatorEvaluatorInstance;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.EnforceContext;
import org.casbin.jcasbin.util.SyncedLRUCache;
import org.casbin.jcasbin.util.Util;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class TestUtil {
    static void testEnforce(Enforcer e, Object sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, obj, act));
    }

    static void testEnforceWithMatcher(Enforcer e, String matcher, Object sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforceWithMatcher(matcher, sub, obj, act));
    }

    static void testEnforceEx(Enforcer e, Object sub, Object obj, String act, boolean res, String[] explain) {
        EnforceResult enforceResult = e.enforceEx(sub, obj, act);
        assertEquals(res, enforceResult.isAllow());
        for (int i = 0; i < explain.length; i++) {
            assertEquals(explain[i], enforceResult.getExplain().get(i));
        }
    }

    static void testEnforceExWithMatcher(Enforcer e, String matcher, Object sub, Object obj, String act, boolean res, String[] explain) {
        EnforceResult enforceResult = e.enforceExWithMatcher(matcher, sub, obj, act);
        assertEquals(res, enforceResult.isAllow());
        for (int i = 0; i < explain.length; i++) {
            assertEquals(explain[i], enforceResult.getExplain().get(i));
        }
    }

    static void testEnforceWithoutUsers(Enforcer e, String obj, String act, boolean res) {
        assertEquals(res, e.enforce(obj, act));
    }

    static void testEnforceWithContext(Enforcer e, EnforceContext enforceContext, Object sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforce(enforceContext, sub, obj, act));
    }

    static void testRBACWithABACRuleEnforce(Enforcer e, Object sub, Object obj, String act, Map<String, Object> ctx, boolean res) {
        assertEquals(res, e.enforce(sub, obj, act, ctx));
    }

    static void testDomainEnforce(Enforcer e, Object sub, Object dom, Object obj, Object act, boolean res) {
        assertEquals(res, e.enforce(sub, dom, obj, act));
    }

    static void testGetPolicy(Enforcer e, List<List<String>> res) {
        List<List<String>> myRes = e.getPolicy();
        Util.logPrint("Policy: " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Policy: " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetFilteredPolicy(Enforcer e, int fieldIndex, List<List<String>> res, String... fieldValues) {
        List<List<String>> myRes = e.getFilteredPolicy(fieldIndex, fieldValues);
        Util.logPrint("Policy for " + Util.paramsToString(fieldValues) + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Policy for " + Util.paramsToString(fieldValues) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetGroupingPolicy(Enforcer e, List<List<String>> res) {
        List<List<String>> myRes = e.getGroupingPolicy();
        Util.logPrint("Grouping policy: " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Grouping policy: " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetFilteredGroupingPolicy(Enforcer e, int fieldIndex, List<List<String>> res, String... fieldValues) {
        List<List<String>> myRes = e.getFilteredGroupingPolicy(fieldIndex, fieldValues);
        Util.logPrint("Grouping policy for " + Util.paramsToString(fieldValues) + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Grouping policy for " + Util.paramsToString(fieldValues) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasPolicy(Enforcer e, List<String> policy, boolean res) {
        boolean myRes = e.hasPolicy(policy);
        Util.logPrint("Has policy " + Util.arrayToString(policy) + ": " + myRes);

        if (res != myRes) {
            fail("Has policy " + Util.arrayToString(policy) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasGroupingPolicy(Enforcer e, List<String> policy, boolean res) {
        boolean myRes = e.hasGroupingPolicy(policy);
        Util.logPrint("Has grouping policy " + Util.arrayToString(policy) + ": " + myRes);

        if (res != myRes) {
            fail("Has grouping policy " + Util.arrayToString(policy) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRoles(Enforcer e, String name, List<String> res) {
        List<String> myRes = e.getRolesForUser(name);
        Util.logPrint("Roles for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRoles(RoleManager rm, String name, List<String> res) {
        List<String> myRes = rm.getRoles(name);
        Util.logPrint("Roles for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRoles(RoleManager rm, String name, String domain, List<String> res) {
        List<String> myRes = rm.getRoles(name, domain);
        Util.logPrint("Roles for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetUsers(Enforcer e, String name, List<String> res) {
        List<String> myRes = e.getUsersForRole(name);
        Util.logPrint("Users for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Users for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetUsers(RoleManager rm, String name, List<String> res) {
        List<String> myRes = rm.getUsers(name);
        Util.logPrint("Users for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Users for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasRole(Enforcer e, String name, String role, boolean res) {
        boolean myRes = e.hasRoleForUser(name, role);
        Util.logPrint(name + " has role " + role + ": " + myRes);

        if (res != myRes) {
            fail(name + " has role " + role + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasRole(RoleManager rm, String name, String role, boolean res) {
        boolean myRes = rm.hasLink(name, role);
        Util.logPrint(name + " has role " + role + ": " + myRes);

        if (res != myRes) {
            fail(name + " has role " + role + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasRole(RoleManager rm, String name, String role, String domain, boolean res) {
        boolean myRes = rm.hasLink(name, role, domain);
        Util.logPrint(domain + " :: " + name + " has role " + role + ": " + myRes);

        if (res != myRes) {
            fail(domain + " :: " + name + " has role " + role + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetPermissions(Enforcer e, String name, List<List<String>> res) {
        List<List<String>> myRes = e.getPermissionsForUser(name);
        Util.logPrint("Permissions for " + name + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetNamedPermissionsForUser(Enforcer e, String pType, String name, List<List<String>> res, String... domain) {
        List<List<String>> myRes = e.getNamedPermissionsForUser(pType, name, domain);
        Util.logPrint("Named permissions for " + name + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Named permissions for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasPermission(Enforcer e, String name, List<String> permission, boolean res) {
        boolean myRes = e.hasPermissionForUser(name, permission);
        Util.logPrint(name + " has permission " + Util.arrayToString(permission) + ": " + myRes);

        if (res != myRes) {
            fail(name + " has permission " + Util.arrayToString(permission) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRolesInDomain(Enforcer e, String name, String domain, List<String> res) {
        List<String> myRes = e.getRolesForUserInDomain(name, domain);
        Util.logPrint("Roles for " + name + " under " + domain + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetUsersInDomain(Enforcer e, String name, String domain, List<String> res) {
        List<String> myRes = e.getUsersForRoleInDomain(name, domain);
        Util.logPrint("Roles for " + name + " under " + domain + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetPermissionsInDomain(Enforcer e, String name, String domain, List<List<String>> res) {
        List<List<String>> myRes = e.getPermissionsForUserInDomain(name, domain);
        Util.logPrint("Permissions for " + name + " under " + domain + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetImplicitPermissionsInDomain(Enforcer e, String name, String domain, List<List<String>> res) {
        List<List<String>> myRes = e.getImplicitPermissionsForUser(name, domain);
        Util.logPrint("Permissions for " + name + " under " + domain + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetNamedImplicitPermissions(Enforcer e, String pType, String name, List<List<String>> res, String... domain) {
        List<List<String>> myRes = e.getNamedImplicitPermissionsForUser(pType, name, domain);
        Util.logPrint("Named implicit permissions for " + name + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Named implicit permissions for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGlobMatch(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.globMatch(key1, key2));
    }

    static void testKeyGet(String key1, String key2, String res) {
        assertEquals(res, BuiltInFunctions.keyGetFunc(key1, key2));
    }

    static void testKeyGet2(String key1, String key2, String pathVar, String res) {
        assertEquals(res, BuiltInFunctions.keyGet2Func(key1, key2, pathVar));
    }

    static void testKeyGet3(String key1, String key2, String pathVar, String res) {
        assertEquals(res, BuiltInFunctions.keyGet3Func(key1, key2, pathVar));
    }

    static void testEval(String eval, Map<String, Object> env, AviatorEvaluatorInstance aviatorEval, boolean res) {
        assertEquals(res, BuiltInFunctions.eval(eval, env, aviatorEval));
    }

    static void testKeyMatch(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.keyMatch(key1, key2));
    }

    static void testKeyMatch2(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.keyMatch2(key1, key2));
    }

    static void testKeyMatch3(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.keyMatch3(key1, key2));
    }

    static void testKeyMatch4(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.keyMatch4(key1, key2));
    }

    static void testKeyMatch5(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.keyMatch5(key1, key2));
    }

    static void testRegexMatch(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.regexMatch(key1, key2));
    }

    static void testIpMatch(String ip1, String ip2, boolean res) {
        assertEquals(res, BuiltInFunctions.ipMatch(ip1, ip2));
    }

    static void testCacheGet(SyncedLRUCache<String, Integer> cache, String key, Integer value, boolean res) {
        assertEquals(res, value.equals(cache.get(key)));
    }

    static void testCachePut(SyncedLRUCache<String, Integer> cache, String key, Integer value) {
        cache.put(key, value);
        if (!value.equals(cache.get(key))) {
            fail("Put(" + key + ", " + value + "): didn't add value");
        }
    }
}
