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

package org.casbin.jcasbin.rbac;

import org.casbin.jcasbin.util.SyncedLRUCache;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
public class DomainManager implements RoleManager {
    private static final String DEFAULT_DOMAIN = "casbin::default";
    // Keep explicit links separate from the domain views built by matching.
    private Map<String, DefaultRoleManager> rmMap;
    private Map<String, DefaultRoleManager> matchedRmMap;
    private int maxHierarchyLevel;
    private BiPredicate<String, String> matchingFunc;
    private BiPredicate<String, String> domainMatchingFunc;
    private SyncedLRUCache<String, Boolean> domainMatchingFuncCache;

    public DomainManager(int maxHierarchyLevel) {
        this(maxHierarchyLevel, null, null);
    }

    public DomainManager(int maxHierarchyLevel, final BiPredicate<String, String> matchingFunc,
                         final BiPredicate<String, String> domainMatchingFunc) {
        clear();
        this.maxHierarchyLevel = maxHierarchyLevel;
        this.matchingFunc = matchingFunc;
        this.domainMatchingFunc = domainMatchingFunc;
    }

    public void addMatchingFunc(String name, BiPredicate<String, String> matchingFunc) {
        this.matchingFunc = matchingFunc;
        this.rmMap.values().forEach(rm -> rm.addMatchingFunc(name, matchingFunc));
        this.matchedRmMap.clear();
    }

    public void addDomainMatchingFunc(String name, BiPredicate<String, String> domainMatchingFunc) {
        this.domainMatchingFunc = domainMatchingFunc;
        this.domainMatchingFuncCache = new SyncedLRUCache<>(100);
        this.matchedRmMap.clear();
    }

    private String domainName(String... domain) {
        return domain.length == 0 ? DEFAULT_DOMAIN : domain[0];
    }

    private DefaultRoleManager getRoleManager(String domain) {
        DefaultRoleManager rm = this.rmMap.get(domain);
        if (rm == null) {
            rm = new DefaultRoleManager(this.maxHierarchyLevel, this.matchingFunc, null);
            this.rmMap.put(domain, rm);
        }
        return rm;
    }

    private DefaultRoleManager getMatchedRoleManager(String domain) {
        if (this.domainMatchingFunc == null) {
            DefaultRoleManager rm = this.rmMap.get(domain);
            return rm != null ? rm : new DefaultRoleManager(this.maxHierarchyLevel, this.matchingFunc, null);
        }
        DefaultRoleManager rm = this.matchedRmMap.get(domain);
        if (rm == null) {
            rm = new DefaultRoleManager(this.maxHierarchyLevel, this.matchingFunc, null);
            for (Map.Entry<String, DefaultRoleManager> entry : this.rmMap.entrySet()) {
                if (domain.equals(entry.getKey()) || match(domain, entry.getKey())) {
                    rm.copyFrom(entry.getValue());
                }
            }
            // Do not retain views for arbitrary domains supplied by requests.
            if (this.rmMap.containsKey(domain)) {
                this.matchedRmMap.put(domain, rm);
            }
        }
        return rm;
    }

    private boolean match(String str, String pattern) {
        String cacheKey =  String.join("$$", str, pattern);
        Boolean matched = this.domainMatchingFuncCache.get(cacheKey);
        if (matched == null) {
            if (this.domainMatchingFunc != null) {
                matched = this.domainMatchingFunc.test(str, pattern);
            } else {
                matched = str.equals(pattern);
            }
            this.domainMatchingFuncCache.put(cacheKey, matched);
        }
        return matched;
    }

    @Override
    public void clear() {
        this.rmMap = new HashMap<>();
        this.matchedRmMap = new HashMap<>();
        this.domainMatchingFuncCache = new SyncedLRUCache<>(100);
    }

    @Override
    public void addLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain));
        roleManager.addLink(name1, name2, domain);
        this.matchedRmMap.clear();
    }

    @Override
    public void deleteLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain));
        roleManager.deleteLink(name1, name2, domain);
        this.matchedRmMap.clear();
    }

    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getMatchedRoleManager(domainName(domain));
        return roleManager.hasLink(name1, name2, domain);
    }

    @Override
    public List<String> getRoles(String name, String... domain) {
        DefaultRoleManager roleManager = getMatchedRoleManager(domainName(domain));
        return roleManager.getRoles(name, domain);
    }

    @Override
    public List<String> getUsers(String name, String... domain) {
        DefaultRoleManager roleManager = getMatchedRoleManager(domainName(domain));
        return roleManager.getUsers(name, domain);
    }

    @Override
    public String toString() {
        List<String> roles = new ArrayList<>();
        this.rmMap.forEach((domain, rm) -> {
            List<String> domainRoles = new ArrayList<>();
            rm.allRoles.values().forEach(role -> {
                if (!"".equals(role.toString())) {
                    domainRoles.add(role.toString());
                }
            });
            roles.add(domain + ": " + String.join(", ", domainRoles));
        });
        return String.join("\n", roles);
    }

    @Override
    public void printRoles() {
        Util.logPrintfInfo("{}", this);
    }
}
