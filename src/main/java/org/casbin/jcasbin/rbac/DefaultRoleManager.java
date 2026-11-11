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

import org.casbin.jcasbin.detector.Detector;
import org.casbin.jcasbin.util.SyncedLRUCache;
import org.casbin.jcasbin.util.Util;

import java.util.*;
import java.util.function.BiPredicate;

public class DefaultRoleManager implements RoleManager {
    private static final String DEFAULT_DOMAIN = "casbin::default";
    Map<String, Role> allRoles;
    final int maxHierarchyLevel;

    BiPredicate<String, String> matchingFunc;
    private SyncedLRUCache<String, Boolean> matchingFuncCache;
    private Detector detector;

    /**
     * Sets the checker used after adding role links. A null detector disables checking.
     * Existing links are not checked until the next call to addLink.
     *
     * @param detector the optional role consistency checker
     */
    public void setDetector(Detector detector) {
        this.detector = detector;
    }

    /**
     * DefaultRoleManager is the constructor for creating an instance of the default RoleManager
     * implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    public DefaultRoleManager(int maxHierarchyLevel) {
        this(maxHierarchyLevel, null, null);
    }

    /**
     * In order to use a specific role name matching function, set explicitly the role manager on
     * the Enforcer and rebuild role links (you can optimize by using minimal enforcer constructor).
     *
     * <pre>
     * final Enforcer e = new Enforcer("model.conf");
     * e.setAdapter(new FileAdapter("policies.csv"));
     * e.setRoleManager(new DefaultRoleManager(10, BuiltInFunctions::domainMatch));
     * e.loadPolicy();
     * </pre>
     *
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     * @param matchingFunc a matcher for supporting pattern in g
     * @param domainMatchingFunc a matcher for supporting domain pattern in g
     */
    public DefaultRoleManager(int maxHierarchyLevel, final BiPredicate<String, String> matchingFunc,
            final BiPredicate<String, String> domainMatchingFunc) {
        this.clear();
        this.maxHierarchyLevel = maxHierarchyLevel;
        this.matchingFunc = matchingFunc;
    }

    /**
     * addMatchingFunc support use pattern in g.
     *
     * @param name the name of the matching function.
     * @param matchingFunc the matching function.
     */
    public void addMatchingFunc(String name, BiPredicate<String, String> matchingFunc) {
        this.matchingFunc = matchingFunc;
        rebuild();
    }

    /**
     * addDomainMatchingFunc support use domain pattern in g
     *
     * @param name the name of the domain matching function.
     * @param domainMatchingFunc the domain matching function.
     */
    public void addDomainMatchingFunc(String name, BiPredicate<String, String> domainMatchingFunc) {
    }

    private void rebuild() {
        Map<String, Role> roles = new HashMap<>(this.allRoles);
        this.clear();
        roles.values().forEach(user -> {
            user.getAllRoles().keySet().forEach(roleName -> addLink(user.getName(), roleName, DEFAULT_DOMAIN));
        });
    }

    boolean match(String str, String pattern) {
        String cacheKey =  String.join("$$", str, pattern);
        Boolean matched = this.matchingFuncCache.get(cacheKey);
        if (matched == null) {
            if (this.matchingFunc != null) {
                matched = this.matchingFunc.test(str, pattern);
            } else {
                matched = str.equals(pattern);
            }
            this.matchingFuncCache.put(cacheKey, matched);
        }
        return matched;
    }

    Role getRole(String name) {
        Role role = this.allRoles.get(name);
        if (role == null) {
            role = new Role(name);
            this.allRoles.put(name, role);

            if (this.matchingFunc != null) {
                for (Map.Entry<String, Role> entry : this.allRoles.entrySet()) {
                    String name2 = entry.getKey();
                    Role role2 = entry.getValue();

                    if (!name.equals(name2) && match(name, name2)) {
                        role2.addMatch(role);
                    }
                    if (!name.equals(name2) && match(name2, name)) {
                        role.addMatch(role2);
                    }
                }
            }
        }

        return role;
    }

    void removeRole(String name) {
        final Role role = this.allRoles.get(name);
        if (role != null) {
            this.allRoles.remove(name);
            role.removeMatches();
        }
    }

    void copyFrom(DefaultRoleManager other) {
        other.allRoles.values().forEach(user -> {
            user.roles.keySet().forEach(roleName -> {
                addLink(user.getName(), roleName, DEFAULT_DOMAIN);
            });
        });
    }

    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    @Override
    public void clear() {
        this.matchingFuncCache = new SyncedLRUCache<>(100);
        this.allRoles = new HashMap<>();
    }

    /**
     * addLink adds the inheritance link between role: name1 and role: name2. aka role: name1
     * inherits role: name2. domain is a prefix to the roles.
     */
    @Override
    public void addLink(String name1, String name2, String... domain) {
        Role user = getRole(name1);
        Role role = getRole(name2);
        boolean existingLink = user.roles.containsKey(name2);
        user.addRole(role);
        if (detector != null) {
            try {
                String error = detector.check(this);
                if (error != null && !error.isEmpty()) {
                    throw new IllegalArgumentException(error);
                }
            } catch (RuntimeException ex) {
                if (!existingLink) {
                    user.removeRole(role);
                }
                throw ex;
            }
        }
    }

    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2. aka role: name1
     * does not inherit role: name2 any more. domain is a prefix to the roles.
     */
    @Override
    public void deleteLink(String name1, String name2, String... domain) {
        Role user = getRole(name1);
        Role role = getRole(name2);
        user.removeRole(role);
    }

    /**
     * hasLink determines whether role: name1 inherits role: name2. domain is a prefix to the roles.
     */
    @Override
    public synchronized boolean hasLink(String name1, String name2, String... domain) {
        if (name1.equals(name2) || (this.matchingFunc != null && this.matchingFunc.test(name1, name2))) {
            return true;
        }

        boolean userCreated = !this.allRoles.containsKey(name1);
        boolean roleCreated = !this.allRoles.containsKey(name2);
        Role user = getRole(name1);
        Role role = getRole(name2);

        try {
            return hasLinkHelper(role.getName(), Collections.singletonMap(user.getName(), user), this.maxHierarchyLevel);
        } finally {
            if (userCreated) {
                removeRole(user.getName());
            }
            if (roleCreated) {
                removeRole(role.getName());
            }
        }
    }

    private boolean hasLinkHelper(String targetName, Map<String, Role> roles, int level) {
        if (level < 0 || roles.size() == 0) {
            return false;
        }

        Map<String, Role> nextRoles = new HashMap<>();
        for (Map.Entry<String, Role> entry : roles.entrySet()) {
            Role role = entry.getValue();
            if (targetName.equals(role.getName()) || (this.matchingFunc != null && match(role.getName(), targetName))) {
                return true;
            }

            nextRoles.putAll(role.getAllRoles());
        }

        return hasLinkHelper(targetName, nextRoles, level - 1);
    }

    /**
     * getRoles gets the roles that a subject inherits. domain is a prefix to the roles.
     */
    @Override
    public List<String> getRoles(String name, String... domain) {
        boolean created = !this.allRoles.containsKey(name);
        Role user = getRole(name);
        try {
            return user.getRoles();
        } finally {
            if (created) {
                removeRole(user.getName());
            }
        }
    }

    /**
     * getUsers gets the users that inherits a subject.
     */
    @Override
    public List<String> getUsers(String name, String... domain) {
        boolean created = !this.allRoles.containsKey(name);
        Role role = getRole(name);
        try {
            return role.getUsers();
        } finally {
            if (created) {
                removeRole(role.getName());
            }
        }
    }

    @Override
    public String toString() {
        List<String> roles = new ArrayList<>();
        this.allRoles.values().forEach(role -> {
            if (!"".equals(role.toString())) {
                roles.add(role.toString());
            }
        });
        return String.join("\n", roles);
    }

    /**
     * printRoles prints all the roles to log.
     */
    @Override
    public void printRoles() {
        Util.logPrintfInfo("{}", this);
    }

    /**
     * getRoleGraph returns the dependency graph (adjacency list) of roles.
     * Each key represents a role name, and the corresponding value is a list of role names
     * that the key role inherits from (parent roles).
     * 
     * @return a defensive copy of the role inheritance graph
     */
    @Override
    public Map<String, List<String>> getRoleGraph() {
        Map<String, List<String>> graph = new HashMap<>();
        for (String roleName : allRoles.keySet()) {
            List<String> parentRoles = getRoles(roleName);
            graph.put(roleName, new ArrayList<>(parentRoles));
        }
        return graph;
    }
}
