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

package org.casbin.jcasbin.model;

import org.casbin.jcasbin.rbac.ConditionalRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Policy represents the whole access control policy user defined.
 */
public class Policy {
    public Map<String, Map<String, Assertion>> model;

    /**
     * buildRoleLinks initializes the roles in RBAC.
     *
     * @param rmMap the role manager map.
     */
    public void buildRoleLinks(Map<String, RoleManager> rmMap) {
        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String ptype = entry.getKey();
                Assertion ast = entry.getValue();
                RoleManager rm = rmMap.get(ptype);
                if (rm != null) {
                    ast.buildRoleLinks(rm);
                }
            }
        }
    }

    /**
     * printPolicy prints the policy to log.
     */
    public void printPolicy() {
        if (!Util.isLogPrintEnabled()) {
            return;
        }
        Util.logPrint("Policy:");
        if (model.containsKey("p")) {
            for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }

        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }
    }

    /**
     * savePolicyToText saves the policy to the text.
     *
     * @return the policy text.
     */
    public String savePolicyToText() {
        StringBuilder res = new StringBuilder();

        if (model.containsKey("p")) {
            for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(String.format("%s, %s\n", key, String.join(", ", rule)));
                }
            }
        }

        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(String.format("%s, %s\n", key, String.join(", ", rule)));
                }
            }
        }

        return res.toString();
    }

    /**
     * clearPolicy clears all current policy.
     */
    public void clearPolicy() {
        if (model.containsKey("p")) {
            for (Assertion ast : model.get("p").values()) {
                ast.policy = new ArrayList<>();
                ast.policyIndex = new HashMap<>();
            }
        }

        if (model.containsKey("g")) {
            for (Assertion ast : model.get("g").values()) {
                ast.policy = new ArrayList<>();
                ast.policyIndex = new HashMap<>();
            }
        }
    }

    /**
     * getPolicy gets all rules in a policy.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @return the policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getPolicy(String sec, String ptype) {
        return model.get(sec).get(ptype).policy;
    }

    /**
     * getFilteredPolicy gets rules based on field filters from a policy.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> res = new ArrayList<>();

        for (List<String> rule : model.get(sec).get(ptype).policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i++) {
                String fieldValue = fieldValues[i];
                if (fieldValue != null && !"".equals(fieldValue) && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                res.add(rule);
            }
        }

        return res;
    }

    /**
     * hasPolicy determines whether a model has the specified policy rule.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(String sec, String ptype, List<String> rule) {
        return model.get(sec).get(ptype).policyIndex.containsKey(Assertion.policyKey(rule));
    }

    /**
     * addPolicy adds a policy rule to the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return succeeds or not.
     */
    public boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (!hasPolicy(sec, ptype, rule)) {
            Assertion assertion = model.get(sec).get(ptype);
            List<List<String>> policy = assertion.policy;
            int priorityIndex = assertion.priorityIndex;

            // ensure the policies is ordered by priority value
            if ("p".equals(sec) && priorityIndex >= 0) {
                int value = Integer.parseInt(rule.get(priorityIndex));
                int left = 0, right = policy.size();
                // binary insert
                while (left < right) {
                    int mid = (left + right) >>> 1;
                    if (value > Integer.parseInt(policy.get(mid).get(priorityIndex))) {
                        left = mid + 1;
                    } else {
                        right = mid;
                    }
                }
                policy.add(left, rule);
                for (int i = left; i < assertion.policy.size(); ++i) {
                    assertion.policyIndex.put(Assertion.policyKey(assertion.policy.get(i)), i);
                }
            } else {
                policy.add(rule);
                assertion.policyIndex.put(Assertion.policyKey(rule), policy.size() - 1);
            }

            return true;
        }

        return false;
    }

    /**
     * addPolicies adds policy rules to the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean addPolicies(String sec, String ptype, List<List<String>> rules) {
        int size = model.get(sec).get(ptype).policy.size();
        for (List<String> rule : rules) {
            if (!hasPolicy(sec, ptype, rule)) {
                addPolicy(sec, ptype, rule);
            }
        }
        return size < model.get(sec).get(ptype).policy.size();
    }

    /**
     * UpdatePolicy updates a policy rule from the model.
     *
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param oldRule the old rule.
     * @param newRule the new rule.
     * @return succeeds or not.
     */
    public boolean updatePolicy(String sec, String ptype, List<String> oldRule, List<String> newRule) {
        if (!hasPolicy(sec, ptype, oldRule)) {
            return false;
        }
        Assertion ast = model.get(sec).get(ptype);
        int index = ast.policyIndex.get(Assertion.policyKey(oldRule));
        ast.policy.set(index, newRule);
        ast.policyIndex.remove(Assertion.policyKey(oldRule));
        ast.policyIndex.put(Assertion.policyKey(newRule), index);
        return true;
    }

    /**
     * removePolicy removes a policy rule from the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return succeeds or not.
     */
    public boolean removePolicy(String sec, String ptype, List<String> rule) {
        Assertion ast = model.get(sec).get(ptype);
        if (ast.policyIndex.containsKey(Assertion.policyKey(rule))) {
            int index = ast.policyIndex.get(Assertion.policyKey(rule));
            ast.policy.remove(index);
            ast.policyIndex.remove(Assertion.policyKey(rule));
            for (int i = index; i < ast.policy.size(); ++i) {
                ast.policyIndex.put(Assertion.policyKey(ast.policy.get(i)), i);
            }

            return true;
        }

        return false;
    }

    /**
     * removePolicies removes rules from the current policy.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean removePolicies(String sec, String ptype, List<List<String>> rules) {
        int size = model.get(sec).get(ptype).policy.size();
        for (List<String> rule : rules) {
            removePolicy(sec, ptype, rule);
        }
        return size > model.get(sec).get(ptype).policy.size();
    }

    /**
     * removeFilteredPolicyReturnsEffects removes policy rules based on field filters from the model.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds(effects.size () &gt; 0) or not.
     */
    public List<List<String>> removeFilteredPolicyReturnsEffects(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> tmp = new ArrayList<>();
        List<List<String>> effects = new ArrayList<>();
        int firstIndex = -1;

        for (List<String> rule : model.get(sec).get(ptype).policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i++) {
                String fieldValue = fieldValues[i];
                if (!"".equals(fieldValue) && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                if (firstIndex == -1) {
                    firstIndex = model.get(sec).get(ptype).policy.indexOf(rule);
                }
                effects.add(rule);
            } else {
                tmp.add(rule);
            }
        }

        if (firstIndex != -1) {
            Assertion assertion = model.get(sec).get(ptype);
            assertion.policy = tmp;
            assertion.policyIndex.clear();
            for (int i = 0; i < assertion.policy.size(); ++i) {
                assertion.policyIndex.put(Assertion.policyKey(assertion.policy.get(i)), i);
            }
        }

        return effects;
    }

    /**
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        return removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues).size() > 0;
    }

    /**
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param sec        the section, "p" or "g".
     * @param ptype      the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's index.
     * @return the field values specified by fieldIndex.
     */
    public List<String> getValuesForFieldInPolicy(String sec, String ptype, int fieldIndex) {
        List<String> values = new ArrayList<>();

        for (List<String> rule : model.get(sec).get(ptype).policy) {
            values.add(rule.get(fieldIndex));
        }

        values = Util.arrayRemoveDuplicates(values);

        return values;
    }

    public void buildIncrementalRoleLinks(Map<String, RoleManager> rmMap, Model.PolicyOperations op, String sec, String ptype, List<List<String>> rules) {
        if ("g".equals(sec) && rmMap.containsKey(ptype)) {
            model.get(sec).get(ptype).buildIncrementalRoleLinks(rmMap.get(ptype), op, rules);
        }
    }

    public boolean hasPolicies(String sec, String ptype, List<List<String>> rules) {
        for (List<String> rule : rules) {
            if (this.hasPolicy(sec, ptype, rule)) {
                return true;
            }
        }
        return false;
    }

    /**
     * buildIncrementalConditionalRoleLinks provides incremental build the role inheritance relations.
     *
     * @param condRmMap a map of conditional role managers used for role link management.
     * @param op        the operation to perform, such as adding or removing role links.
     * @param sec       the section of the policy, typically "g" for role inheritance.
     * @param ptype     the policy type, which specifies the kind of roles being managed.
     * @param rules     the rules that define the role links to be built.
     */
    public void buildIncrementalConditionalRoleLinks(Map<String, ConditionalRoleManager> condRmMap, Model.PolicyOperations op, String sec, String ptype, List<List<String>> rules){
        if ("g".equals(sec) && condRmMap.containsKey(ptype)) {
            model.get(sec).get(ptype).buildIncrementalConditionalRoleLinks(condRmMap.get(ptype), op, rules);
        }
    }

    /**
     * buildConditionalRoleLinks initializes the roles in RBAC.
     *
     * @param condRmMap a map of conditional role managers that manage the role links and their conditions.
     */
    public void buildConditionalRoleLinks(Map<String, ConditionalRoleManager> condRmMap){
        printPolicy();
        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String ptype = entry.getKey();
                Assertion ast = entry.getValue();
                if (condRmMap.get(ptype) != null){
                    ConditionalRoleManager condRm = condRmMap.get(ptype);
                    ast.buildConditionalRoleLinks(condRm);
                }
            }
        }
    }
}
