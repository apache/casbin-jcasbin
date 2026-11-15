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

import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.BatchAdapter;
import org.casbin.jcasbin.persist.UpdatableAdapter;
import org.casbin.jcasbin.persist.WatcherEx;
import org.casbin.jcasbin.persist.WatcherUpdatable;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.singletonList;

/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 */
class InternalEnforcer extends CoreEnforcer {

    /**
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules       the policies
     * @param updateType  the UpdateType
     * @return            indicate whether the notification to the Watcher is successful or not
     */
    private boolean notifyWatcher(String sec, String ptype, List<List<String>> rules, WatcherEx.UpdateType updateType) {
        if(watcher == null || !autoNotifyWatcher) return true;
        try {
            if (watcher instanceof WatcherEx) switch (updateType) {
                case UpdateForAddPolicy:
                    ((WatcherEx) watcher).updateForAddPolicy(sec, ptype, rules.get(0).toArray(new String[0]));
                    break;
                case UpdateForRemovePolicy:
                    ((WatcherEx) watcher).updateForRemovePolicy(sec, ptype, rules.get(0).toArray(new String[0]));
                    break;
                case UpdateForAddPolicies:
                    ((WatcherEx) watcher).updateForAddPolicies(sec, ptype, rules);
                    break;
                case UpdateForRemovePolicies:
                    ((WatcherEx) watcher).updateForRemovePolicies(sec, ptype, rules);
                    break;
                default:
                    Util.logPrint("UnsupportedUpdateType for notifyWatcher");
                    break;
            } else {
                watcher.update();
            }
        } catch (Exception e) {
            Util.logPrint("An exception occurred:" + e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * addPolicy adds a rule to the current policy.
     */
    boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (mustUseDispatcher()) {
            dispatcher.addPolicies(sec, ptype, singletonList(rule));
            return true;
        }

        if (model.hasPolicy(sec, ptype, rule)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                adapter.addPolicy(sec, ptype, rule);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        model.addPolicy(sec, ptype, rule);

        buildIncrementalRoleLinks(sec, ptype, singletonList(rule), Model.PolicyOperations.POLICY_ADD);
        bumpPolicyVersion();

        return notifyWatcher(sec, ptype, singletonList(rule), WatcherEx.UpdateType.UpdateForAddPolicy);
    }


    /**
     * addPolicies adds rules to the current policy.
     */
    boolean addPolicies(String sec, String ptype, List<List<String>> rules, boolean autoRemoveRepeat) {
        if(autoRemoveRepeat) {
            for (List<String> rule : rules) {
                if(model.hasPolicy(sec, ptype, rule)) {
                    model.removePolicy(sec, ptype, rule);
                    bumpPolicyVersion();
                }
            }
        }

        if (mustUseDispatcher()) {
            dispatcher.addPolicies(sec, ptype, rules);
            return true;
        }

        if (model.hasPolicies(sec, ptype, rules)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).addPolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        model.addPolicies(sec, ptype, rules);

        buildIncrementalRoleLinks(sec, ptype, rules, Model.PolicyOperations.POLICY_ADD);
        bumpPolicyVersion();

        return notifyWatcher(sec, ptype, rules, WatcherEx.UpdateType.UpdateForAddPolicies);
    }

    /**
     * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
     * @param op Policy operations.
     * @param ptype policy type.
     * @param rules the rules.
     */
    public void buildIncrementalRoleLinks(Model.PolicyOperations op, String ptype, List<List<String>> rules) {
        model.buildIncrementalRoleLinks(rmMap, op, "g", ptype, rules);
        bumpPolicyVersion();
    }

    /**
     * removePolicy removes a rule from the current policy.
     */
    boolean removePolicy(String sec, String ptype, List<String> rule) {
        if (mustUseDispatcher()) {
            dispatcher.removePolicies(sec, ptype, singletonList(rule));
            return true;
        }

        if (adapter != null && autoSave) {
            try {
                adapter.removePolicy(sec, ptype, rule);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        boolean ruleRemoved = model.removePolicy(sec, ptype, rule);

        if (!ruleRemoved) {
            return false;
        }

        buildIncrementalRoleLinks(sec, ptype, singletonList(rule), Model.PolicyOperations.POLICY_REMOVE);
        bumpPolicyVersion();

        return notifyWatcher(sec, ptype, singletonList(rule), WatcherEx.UpdateType.UpdateForRemovePolicy);
    }

    /**
     * updatePolicy updates an authorization rule from the current policy.
     *
     * @param sec     the section, "p" or "g".
     * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param oldRule the old rule.
     * @param newRule the new rule.
     * @return succeeds or not.
     */
    boolean updatePolicy(String sec, String ptype, List<String> oldRule, List<String> newRule) {
        if (mustUseDispatcher()) {
            dispatcher.updatePolicy(sec, ptype, oldRule, newRule);
            return true;
        }

        if (adapter != null && autoSave) {
            if (adapter instanceof UpdatableAdapter) {
                try {
                    ((UpdatableAdapter) adapter).updatePolicy(sec, ptype, oldRule, newRule);
                } catch (UnsupportedOperationException ignored) {
                    Util.logPrint("Method not implemented");
                } catch (Exception e) {
                    Util.logPrint("An exception occurred:" + e.getMessage());
                    return false;
                }
            }
        }

        boolean ruleUpdated = model.updatePolicy(sec, ptype, oldRule, newRule);

        if (!ruleUpdated) {
            return false;
        }
        bumpPolicyVersion();

        if ("g".equals(sec)) {
            try {
                // remove the old rule
                List<List<String>> oldRules = new ArrayList<>();
                oldRules.add(oldRule);
                buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, oldRules);
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }

            try {
                // add the new rule
                List<List<String>> newRules = new ArrayList<>();
                newRules.add(newRule);
                buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_ADD, ptype, newRules);
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }
        bumpPolicyVersion();

        if (watcher != null && autoNotifyWatcher) {
            try {
                if (watcher instanceof WatcherUpdatable) {
                    ((WatcherUpdatable) watcher).updateForUpdatePolicy(oldRule, newRule);
                } else {
                    watcher.update();
                }
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        return true;
    }

    /**
     * removePolicies removes rules from the current policy.
     */
    boolean removePolicies(String sec, String ptype, List<List<String>> rules) {
        if (mustUseDispatcher()) {
            dispatcher.removePolicies(sec, ptype, rules);
            return true;
        }

        if (!model.hasPolicies(sec, ptype, rules)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).removePolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        boolean rulesRemoved = model.removePolicies(sec, ptype, rules);

        if (!rulesRemoved) {
            return false;
        }

        buildIncrementalRoleLinks(sec, ptype, rules, Model.PolicyOperations.POLICY_REMOVE);
        bumpPolicyVersion();

        return notifyWatcher(sec, ptype, rules, WatcherEx.UpdateType.UpdateForRemovePolicies);
    }

    /**
     * removeFilteredPolicy removes rules based on field filters from the current policy.
     */
    boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        if (mustUseDispatcher()) {
            dispatcher.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            return true;
        }

        if (fieldValues == null || fieldValues.length == 0) {
            Util.logPrint("Invalid fieldValues parameter");
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrint("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        List<List<String>> effects = model.removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues);
        boolean ruleRemoved = effects.size() > 0;

        if (!ruleRemoved) {
            return false;
        }

        buildIncrementalRoleLinks(sec, ptype, effects, Model.PolicyOperations.POLICY_REMOVE);
        bumpPolicyVersion();

        if (watcher != null && autoNotifyWatcher) {
            // error intentionally ignored
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            } else {
                watcher.update();
            }
        }

        return true;
    }

    int getDomainIndex(String ptype) {
        Assertion ast = model.model.get("p").get(ptype);
        String pattern = String.format("%s_dom", ptype);
        int index = ast.tokens.length;
        for (int i = 0; i < ast.tokens.length; i++) {
            if (ast.tokens[i].equals(pattern)) {
                index = i;
                break;
            }
        }
        return index;
    }

    private void buildIncrementalRoleLinks(
        final String sec,
        final String ptype,
        final List<List<String>> rules,
        final Model.PolicyOperations operation
    ) {
        if ("g".equals(sec)) {
            buildIncrementalRoleLinks(operation, ptype, rules);
        }
    }
}
