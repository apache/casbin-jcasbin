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

import org.casbin.jcasbin.effect.Effect;
import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.util.Util;

import java.util.*;
import java.util.stream.Collectors;

/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 */
public class ManagementEnforcer extends InternalEnforcer {
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    public List<String> getAllSubjects() {
        return getAllNamedSubjects("p");
    }

    /**
     * GetAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make sure
     *         your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedSubjects(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 0);
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllObjects() {
        return getAllNamedObjects("p");
    }

    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the objects in policy rules of the ptype type. It actually
     *         collects the 1-index elements of the policy rules. So make sure
     *         your object is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedObjects(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 1);
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllActions() {
        return getAllNamedActions("p");
    }

    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the actions in policy rules of the ptype type. It actually
     *         collects the 2-index elements of the policy rules. So make sure
     *         your action is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedActions(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 2);
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    public List<String> getAllRoles() {
        return getAllNamedRoles("g");
    }

    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make
     *         sure your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedRoles(String ptype) {
        return model.getValuesForFieldInPolicy("g", ptype, 1);
    }

    /**
     * getAllUsers gets the list of users that show up in the current policy.
     * Users are subjects that are not roles (i.e., subjects that do not appear
     * as the second element in any grouping policy).
     *
     * @return all users in "p" policy rules, excluding roles defined in "g" rules.
     */
    public List<String> getAllUsers() {
        return getAllNamedUsers("p");
    }

    /**
     * getAllNamedUsers gets the list of users that show up in the named policy.
     * Users are subjects that are not roles.
     *
     * @param ptype the policy type, e.g., "p", "p2".
     * @return all users in the named policy, excluding roles defined in "g" rules.
     */
    public List<String> getAllNamedUsers(String ptype) {
        List<String> subjects = getAllNamedSubjects(ptype);
        List<String> roles = getAllRoles();
        return Util.setSubtract(subjects, roles);
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    public List<List<String>> getPolicy() {
        return getNamedPolicy("p");
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    public List<List<String>> getFilteredPolicy(int fieldIndex, String... fieldValues) {
        return getFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    public List<List<String>> getNamedPolicy(String ptype) {
        return model.getPolicy("p", ptype);
    }

    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules of the specified ptype.
     */
    public List<List<String>> getFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return model.getFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    public List<List<String>> getGroupingPolicy() {
        return getNamedGroupingPolicy("g");
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
                          means not to match this field.
     * @return the filtered "g" policy rules.
     */
    public List<List<String>> getFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return getFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    public List<List<String>> getNamedGroupingPolicy(String ptype) {
        return model.getPolicy("g", ptype);
    }

    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "g" policy rules of the specified ptype.
     */
    public List<List<String>> getFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return model.getFilteredPolicy("g", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(List<String> params) {
        return hasNamedPolicy("p", params);
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(String... params) {
        return hasPolicy(Arrays.asList(params));
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedPolicy(String ptype, List<String> params) {
        return model.hasPolicy("p", ptype, params);
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedPolicy(String ptype, String... params) {
        return hasNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicy(List<String> params) {
        return addNamedPolicy("p", params);
    }

    /**
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding rule by adding the new rule.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicies(List<List<String>> rules) {
        return addNamedPolicies("p", rules);
    }

    /**
     * updatePolicy update an authorization rule to the current policy.
     *
     * @param params1  the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    public boolean updatePolicy(List<String> params1, List<String> params2) {
        return updateNamedPolicy("p", params1, params2);
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicy(String... params) {
        return addPolicy(Arrays.asList(params));
    }

    /**
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding rule by adding the new rule.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicies(String[][] rules) {
        return addPolicies(Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedPolicy(String ptype, List<String> params) {
        return addPolicy("p", ptype, params);
    }

    /**
     * addNamedPolicies adds authorization rules to the current named policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedPolicies(String ptype, List<List<String>> rules) {
        return addPolicies("p", ptype, rules, false);
    }

    /**
     * addNamedPoliciesEx adds authorization rules to the current named policy.
     * If the rule already exists, the rule will not be added.
     * But unlike AddNamedPolicies, other non-existent rules are added instead of returning false directly
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedPoliciesEx(String ptype, List<List<String>> rules) {
        return addPolicies("p", ptype, rules, true);
    }

    /**
     * updateNamedPolicy updates an authorization rule to the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params1  the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    public boolean updateNamedPolicy(String ptype, List<String> params1, List<String> params2) {
        return updatePolicy("p", ptype, params1, params2);
    }

    /**
     * UpdateGroupingPolicy updates an authorization rule to the current named policy.
     *
     * @param params1  the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    public boolean updateGroupingPolicy(List<String> params1, List<String> params2) {
        return updateNamedGroupingPolicy("g", params1, params2);
    }

    /**
     * updateNamedGroupingPolicy updates an authorization rule to the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params1  the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    public boolean updateNamedGroupingPolicy(String ptype, List<String> params1, List<String> params2) {
        return updatePolicy("g", ptype, params1, params2);
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedPolicy(String ptype, String... params) {
        return addNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicy(List<String> params) {
        return removeNamedPolicy("p", params);
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicy(String... params) {
        return removePolicy(Arrays.asList(params));
    }

    /**
     * removePolicies removes authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicies(List<List<String>> rules) {
        return removeNamedPolicies("p", rules);
    }

    /**
     * removePolicies removes authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicies(String[][] rules) {
        return removePolicies(Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredPolicy(int fieldIndex, String... fieldValues) {
        return removeFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedPolicy(String ptype, List<String> params) {
        return removePolicy("p", ptype, params);
    }


    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedPolicy(String ptype, String... params) {
        return removeNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removeNamedPolicies removes authorization rules from the current named policy.
     *
     * @param ptype ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    public boolean removeNamedPolicies(String ptype, List<List<String>> rules) {
        return removePolicies("p", ptype, rules);
    }

    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return removeFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasGroupingPolicy(List<String> params) {
        return hasNamedGroupingPolicy("g", params);
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasGroupingPolicy(String... params) {
        return hasGroupingPolicy(Arrays.asList(params));
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, List<String> params) {
        return model.hasPolicy("g", ptype, params);
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, String... params) {
        return hasNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicy(List<String> params) {
        return addNamedGroupingPolicy("g", params);
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicy(String... params) {
        return addGroupingPolicy(Arrays.asList(params));
    }

    /**
     * addGroupingPolicies adds role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicies(List<List<String>> rules) {
        return addNamedGroupingPolicies("g", rules);
    }

    /**
     * addGroupingPolicies adds role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicies(String[][] rules) {
        return addGroupingPolicies(Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleAdded = addPolicy("g", ptype, params);

        return ruleAdded;
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicy(String ptype, String... params) {
        return addNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicies(String ptype, List<List<String>> rules) {
        return addPolicies("g", ptype, rules, false);
    }

    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicies(String ptype, String[][] rules) {
        return addNamedGroupingPolicies(ptype, Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * addGroupingPoliciesEx adds role inheritance rules to the current policy.
     * If the rule already exists, the rule will not be added.
     * But unlike AddGroupingPolicies, other non-existent rules are added instead of returning false directly
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPoliciesEx(List<List<String>> rules) {
        return addNamedGroupingPoliciesEx("g", rules);
    }

    /**
     * addGroupingPoliciesEx adds role inheritance rules to the current policy.
     * If the rule already exists, the rule will not be added.
     * But unlike AddGroupingPolicies, other non-existent rules are added instead of returning false directly
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPoliciesEx(String[][] rules) {
        return addGroupingPoliciesEx(Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * addNamedGroupingPoliciesEx adds named role inheritance rules to the current policy.
     * If the rule already exists, the rule will not be added.
     * But unlike AddNamedGroupingPolicies, other non-existent rules are added instead of returning false directly
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPoliciesEx(String ptype, List<List<String>> rules) {
        return addPolicies("g", ptype, rules, true);
    }

    /**
     * addNamedGroupingPoliciesEx adds named role inheritance rules to the current policy.
     * If the rule already exists, the rule will not be added.
     * But unlike AddNamedGroupingPolicies, other non-existent rules are added instead of returning false directly
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPoliciesEx(String ptype, String[][] rules) {
        return addNamedGroupingPoliciesEx(ptype, Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicy(List<String> params) {
        return removeNamedGroupingPolicy("g", params);
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicy(String... params) {
        return removeGroupingPolicy(Arrays.asList(params));
    }

    /**
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicies(List<List<String>> rules) {
        return removeNamedGroupingPolicies("g", rules);
    }

    /**
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicies(String[][] rules) {
        return removeGroupingPolicies(Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return removeFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleRemoved = removePolicy("g", ptype, params);

        return ruleRemoved;
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicy(String ptype, String... params) {
        return removeNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicies(String ptype, List<List<String>> rules) {
        return removePolicies("g", ptype, rules);
    }

    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicies(String ptype, String[][] rules) {
        return removeNamedGroupingPolicies(ptype, Arrays.stream(rules).map(Arrays::asList).collect(Collectors.toList()));
    }

    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        boolean ruleRemoved = removeFilteredPolicy("g", ptype, fieldIndex, fieldValues);

        return ruleRemoved;
    }

    /**
     * addFunction adds a customized function.
     *
     * @param name the name of the function.
     * @param function the custom function.
     */
    public void addFunction(String name, ExpressionFunction function) {
        fm.addFunction(name, function);
    }

    /**
     * getPermittedActions returns all valid actions to specific object for current subject.
     * At present, the execution efficiency of this method is not high. Please avoid calling this method frequently.
     *
     * @param sub the subject(usually means user).
     * @param obj the object(usually means resources).
     * @return all valid actions to specific object for current subject.
     */
    public Set<String> getPermittedActions(Object sub, Object obj) {
        Assertion ast = model.model.get("p").get("p"); //"sub, obj, act, ..."
        List<List<String>> relations;
        if (model.model.get("g") != null) {
            relations = model.model.get("g").get("g").policy;
        } else {
            relations = Collections.emptyList();
        }

        int actIndex = getElementIndex(ast, "act");
        int objIndex = getElementIndex(ast, "obj");
        int subIndex = getElementIndex(ast, "sub");
        int eftIndex = getElementIndex(ast, "eft");

        Set<String> users = new HashSet<String>() {
            @Override
            public boolean contains(Object o) {
                if (super.contains(o)) return true;
                if (o == null) return super.contains(null);
                for (String s : this) {
                    if (s.equals(o)) return true;
                }
                return false;
            }
        };
        users.add((String)sub);
        int size;
        do {
            size = users.size();
            for (List<String> relation : relations) {
                if (users.contains(relation.get(0))) {
                    users.add(relation.get(1));
                }
            }
        } while (size != users.size());

        List<List<String>> policy = getPolicy();
        Set<String> actionSet = new HashSet<>();
        for (List<String> role : policy) {
            boolean isThisUser = false;
            for (String user : users) {
                if (role.get(subIndex).equals(user)) {
                    isThisUser = true;
                    break;
                }
            }
            if (isThisUser && role.get(objIndex).equals(obj) ) {
                if (eftIndex == -1 || role.get(eftIndex).equalsIgnoreCase(Effect.Allow.toString())) {
                    actionSet.add(role.get(actIndex));
                }
            }
        }
        return actionSet;
    }

    /**
     * getElementIndex returns the index of a specific element.
     * @param policy the policy. For example: policy.value = "sub, obj, act"
     * @param elementName the element's name. For example: elementName = "act"
     * @return the index of a specific element.
     *         If the above two example parameters are passed in, it will return 2.
     *         <tt>-1</tt> if the element does not exist.
     */
    private int getElementIndex(Assertion policy, String elementName) {
        String[] tokens = Util.splitCommaDelimited(policy.value);
        int i = 0;
        for (String token : tokens) {
            if (token.equals(elementName)) {
                return i;
            }
            i++;
        }
        return -1;
    }
}
