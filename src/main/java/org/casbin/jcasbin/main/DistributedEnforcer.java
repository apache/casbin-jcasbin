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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.BatchAdapter;
import org.casbin.jcasbin.persist.UpdatableAdapter;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

/**
 * DistributedEnforcer wraps SyncedEnforcer for dispatcher.
 *
 * @author canxer314
 */
public class DistributedEnforcer extends SyncedEnforcer {

    /**
     * DistributedEnforcer is the default constructor.
     */
    public DistributedEnforcer() {
        super();
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public DistributedEnforcer(String modelPath, String policyFile) {
        super(modelPath, policyFile);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter   the adapter.
     */
    public DistributedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a database adapter and an enable log flag.
     *
     * @param modelPath the path of the model file.
     * @param adapter   the adapter.
     * @param enableLog whether to enable Casbin's log.
     */
    public DistributedEnforcer(String modelPath, Adapter adapter, boolean enableLog) {
        super(modelPath, adapter, enableLog);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m       the model.
     * @param adapter the adapter.
     */
    public DistributedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model, a database adapter and an enable log flag.
     *
     * @param m         the model.
     * @param adapter   the adapter.
     * @param enableLog whether to enable Casbin's log.
     */
    public DistributedEnforcer(Model m, Adapter adapter, boolean enableLog) {
        super(m, adapter, enableLog);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public DistributedEnforcer(Model m) {
        super(m);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public DistributedEnforcer(String modelPath) {
        super(modelPath);
    }

    /**
     * DistributedEnforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog  whether to enable Casbin's log.
     */
    public DistributedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
    }

    /**
     * AddPolicySelf provides a method for dispatcher to add authorization rules to the current policy.
     * The function returns the rules affected and error.
     *
     * @param shouldPersist whether the changes should be persisted.
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules   the rules.
     * @return succeeds or not.
     */
    public List<List<String>> addPolicySelf(BooleanSupplier shouldPersist, String sec, String ptype, List<List<String>> rules) {
        List<List<String>> noExistsPolicy = new ArrayList<>();
        for (List<String> rule : rules) {
            if (!this.model.hasPolicy(sec, ptype, rule)) {
                noExistsPolicy.add(rule);
            }
        }

        if (shouldPersist.getAsBoolean()) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).addPolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return null;
            }
        }

        this.model.addPolicies(sec, ptype, noExistsPolicy);
        bumpPolicyVersion();

        if (sec.equals("g")) {
            try {
                this.buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_ADD, ptype, noExistsPolicy);
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return noExistsPolicy;
            }
        }
        System.out.println();
        return rules;
    }

    /**
     * RemovePolicySelf provides a method for dispatcher to remove policies from current policy.
     * The function returns the rules affected and error.
     *
     * @param shouldPersist whether the changes should be persisted.
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules   the rules.
     * @return succeeds or not.
     */
    public List<List<String>> removePolicySelf(BooleanSupplier shouldPersist, String sec, String ptype, List<List<String>> rules) {
        if (shouldPersist.getAsBoolean()) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).removePolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return null;
            }
        }

        this.model.removePolicies(sec, ptype, rules);
        bumpPolicyVersion();

        if (sec.equals("g")) {
            try {
                this.buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, rules);
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return rules;
            }
        }
        return rules;
    }

    /**
     * RemoveFilteredPolicySelf provides a method for dispatcher to remove an authorization rule from the current policy,
     * field filters can be specified.
     * The function returns the rules affected and error.
     *
     * @param shouldPersist whether the changes should be persisted.
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public List<List<String>> removeFilteredPolicySelf(BooleanSupplier shouldPersist, String sec, String ptype, int fieldIndex, String... fieldValues) {
        if (shouldPersist.getAsBoolean()) {
            try {
                adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return null;
            }
        }

        List<List<String>> effects = this.model.removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues);
        bumpPolicyVersion();

        if (sec.equals("g")) {
            try {
                this.buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, effects);
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return effects;
            }
        }
        return effects;
    }

    /**
     * ClearPolicySelf provides a method for dispatcher to clear all rules from the current policy.
     *
     * @param shouldPersist whether the changes should be persisted.
     */
    public void clearPolicySelf(BooleanSupplier shouldPersist) {
        if (shouldPersist.getAsBoolean()) {
            try {
                adapter.savePolicy(null);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return;
            }
        }
        this.model.clearPolicy();
        if (autoBuildRoleLinks) {
            clearRmMap();
        }
        bumpPolicyVersion();
    }

    /**
     * UpdatePolicySelf provides a method for dispatcher to update an authorization rule from the current policy.
     *
     * @param shouldPersist whether the changes should be persisted.
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param oldRule the old rule.
     * @param newRule the new rule.
     * @return succeeds or not.
     */
    public boolean updatePolicySelf(BooleanSupplier shouldPersist, String sec, String ptype, List<String> oldRule, List<String> newRule) {
        if (shouldPersist.getAsBoolean()) {
            try {
                if (adapter instanceof UpdatableAdapter) {
                    ((UpdatableAdapter) adapter).updatePolicy(sec, ptype, oldRule, newRule);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }
        boolean ruleUpdated = this.model.updatePolicy(sec, ptype, oldRule, newRule);
        if (!ruleUpdated) {
            return false;
        }
        bumpPolicyVersion();
        List<List<String>> rules = new ArrayList<>();
        if (sec.equals("g")) {
            try {
                // remove the old rule
                rules.add(oldRule);
                this.buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, rules);
            } catch (Exception e) {
                return false;
            }
            try {
                // add the new rule
                rules.add(newRule);
                this.buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_ADD, ptype, rules);
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }
}
