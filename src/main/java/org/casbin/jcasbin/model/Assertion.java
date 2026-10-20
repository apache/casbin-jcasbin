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

import org.casbin.jcasbin.log.Logger;
import org.casbin.jcasbin.rbac.ConditionalRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Assertion represents an expression in a section of the model.
 * For example: r = sub, obj, act
 */
public class Assertion {
    public String key;
    public String value;
    public String[] tokens;
    public String[] paramsTokens;
    public List<List<String>> policy;
    public Map<String, Integer> policyIndex;
    public RoleManager rm;
    public ConditionalRoleManager condRM;
    public int priorityIndex;
    private Logger logger;

    public Assertion() {
        policy = new ArrayList<>();
        policyIndex = new HashMap<>();
    }

    public Assertion(Logger logger) {
        policy = new ArrayList<>();
        policyIndex = new HashMap<>();
        setLogger(logger);
    }

    protected void buildRoleLinks(RoleManager rm) {
        this.rm = rm;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '_') {
                count++;
            }
        }
        for (List<String> rule : policy) {
            if (count < 2) {
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
            }
            if (rule.size() < count) {
                throw new IllegalArgumentException("grouping policy elements do not meet role definition");
            }
            if (rule.size() > count){
                rule = rule.subList(0, count);
            }
            this.rm.addLink(rule.get(0), rule.get(1), rule.subList(2, rule.size()).toArray(new String[0]));
        }

        Util.logPrintfInfo("Role links for: {}", key);
        rm.printRoles();
    }

    public void buildIncrementalRoleLinks(RoleManager rm, Model.PolicyOperations op, List<List<String>> rules) {
        this.rm = rm;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '_') {
                count++;
            }
        }
        for (List<String> rule : rules) {
            if (count < 2) {
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
            }
            if (rule.size() < count) {
                throw new IllegalArgumentException("grouping policy elements do not meet role definition");
            }
            if (rule.size() > count) {
                rule = rule.subList(0, count);
            }
            switch (op) {
                case POLICY_ADD:
                    rm.addLink(rule.get(0), rule.get(1), rule.subList(2, rule.size()).toArray(new String[0]));
                    break;
                case POLICY_REMOVE:
                    rm.deleteLink(rule.get(0), rule.get(1), rule.subList(2, rule.size()).toArray(new String[0]));
                    break;
                default:
                    throw new IllegalArgumentException("invalid operation:" + op.toString());
            }
        }
    }

    public void buildIncrementalConditionalRoleLinks(ConditionalRoleManager condRM, Model.PolicyOperations op, List<List<String>> rules){
        this.condRM = condRM;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '_') {
                count++;
            }
        }
        if (count < 2) {
            throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
        }

        for (List<String> rule : rules) {
            if (count < 2) {
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
            }
            if (rule.size() < count) {
                throw new IllegalArgumentException("grouping policy elements do not meet role definition");
            }
            if (rule.size() > count) {
                rule = rule.subList(0, count);
            }
            List<String> domainRule = rule.subList(2, tokens.length);
            switch (op) {
                case POLICY_ADD:
                    addConditionalRoleLink(rule, domainRule);
                    break;
                case POLICY_REMOVE:
                    condRM.deleteLink(rule.get(0), rule.get(1), rule.subList(2, rule.size()).toArray(new String[0]));
                    break;
                default:
                    throw new IllegalArgumentException("invalid operation:" + op.toString());
            }
        }
    }

    public void buildConditionalRoleLinks(ConditionalRoleManager condRM){
        this.condRM = condRM;
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '_') {
                count++;
            }
        }
        for (List<String> rule : policy) {
            if (count < 2) {
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
            }
            if (rule.size() < count) {
                throw new IllegalArgumentException("grouping policy elements do not meet role definition");
            }
            if (rule.size() > count){
                rule = rule.subList(0, count);
            }
            List<String> domainRule = rule.subList(2, tokens.length);
            addConditionalRoleLink(rule, domainRule);
        }

        Util.logPrintfInfo("Role links for: {}", key);
        condRM.printRoles();
    }

    // addConditionalRoleLinks adds Link to rbac.ConditionalRoleManager and sets the parameters for LinkConditionFunc
    public void addConditionalRoleLink(List<String> rule, List<String> domainRule){
        int domainRule_num = (domainRule!=null? domainRule.size() : 0);
        if (domainRule_num == 0){
            condRM.addLink(rule.get(0), rule.get(1));
            condRM.setLinkConditionFuncParams(rule.get(0), rule.get(1), rule.subList(tokens.length, rule.size()).toArray(new String[0]));
            rm = condRM;
        }else {
            String domain = domainRule.get(0);
            condRM.addLink(rule.get(0), rule.get(1), domain);
            condRM.setDomainLinkConditionFuncParams(rule.get(0), rule.get(1), domain, rule.subList(tokens.length, rule.size()).toArray(new String[0]));
            rm = condRM;
        }
    }

    public void initPriorityIndex() {
        priorityIndex = -1;
    }

    public Logger getLogger() {
        return logger;
    }

    public void setLogger(Logger logger) {
        this.logger = logger;
    }
}
