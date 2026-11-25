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

import org.casbin.jcasbin.config.Config;
import org.casbin.jcasbin.log.*;
import org.casbin.jcasbin.util.Util;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.casbin.jcasbin.util.Util.splitCommaDelimited;

/**
 * Model represents the whole access control model.
 */
public class Model extends Policy {
    public static final Map<String, String> sectionNameMap;

    static {
        sectionNameMap = new HashMap<>();
        sectionNameMap.put("r", "request_definition");
        sectionNameMap.put("p", "policy_definition");
        sectionNameMap.put("g", "role_definition");
        sectionNameMap.put("e", "policy_effect");
        sectionNameMap.put("m", "matchers");
    }

    public static final String[] requiredSections = {"r", "p", "e", "m"};

    // used by CoreEnforcer to detect changes to Model
    protected int modCount;
    private int domainIndex = -1;
    private String defaultDomain = "";
    private String defaultSeparator = "::";

    public Model() {
        model = new HashMap<>();
    }

    public int getModCount() {
        return modCount;
    }

    private boolean loadAssertion(Model model, Config cfg, String sec, String key) {
        String value = cfg.getString(sectionNameMap.get(sec) + "::" + key);
        return model.addDef(sec, key, value);
    }

    private static final Pattern paramsPattern = Pattern.compile("\\((.*?)\\)");

    /**
     * getParamsToken Get ParamsToken from Assertion.Value
     */
    private static List<String> getParamsToken(String value) {
        Matcher matcher = paramsPattern.matcher(value);
        if (!matcher.find()) {
            return null;
        }
        String paramsString = matcher.group(1);
        if (paramsString == null || paramsString.isEmpty()) {
            return null;
        }
        String[] paramsArray = paramsString.split(",");
        List<String> paramsList = new ArrayList<>();
        for (String param : paramsArray) {
            paramsList.add(param.trim());
        }
        return paramsList;
    }

    /**
     * addDef adds an assertion to the model.
     *
     * @param sec   the section, "p" or "g".
     * @param key   the policy type, "p", "p2", .. or "g", "g2", ..
     * @param value the policy rule, separated by ", ".
     * @return succeeds or not.
     */
    public boolean addDef(String sec, String key, String value) {
        Assertion ast = new Assertion();
        ast.key = key;
        ast.value = value;
        ast.initPriorityIndex();

        if ("".equals(ast.value)) {
            return false;
        }

        if ("r".equals(sec) || "p".equals(sec)) {
            ast.tokens = splitCommaDelimited(ast.value);
            for (int i = 0; i < ast.tokens.length; i++) {
                ast.tokens[i] = key + "_" + ast.tokens[i];

                if ("p_priority".equals(ast.tokens[i])) {
                    ast.priorityIndex = i;
                }
            }
        } else if ("g".equals(sec)) {
            if (getParamsToken(ast.value) != null){
                ast.paramsTokens =  getParamsToken(ast.value).toArray(new String[0]);
            }
            int paramsTokens_length = ast.paramsTokens==null?0:ast.paramsTokens.length;
            String[] tokens_array = value.split(",");
            List<String> tokens_list = Arrays.asList(tokens_array).subList(0, tokens_array.length - paramsTokens_length);
            ast.tokens = tokens_list.toArray(new String[0]);
        } else {
            ast.value = Util.removeComments(Util.escapeAssertion(ast.value));
        }

        if (!model.containsKey(sec)) {
            model.put(sec, new HashMap<>());
        }

        model.get(sec).put(key, ast);
        modCount++;
        return true;
    }

    private String getKeySuffix(int i) {
        if (i == 1) {
            return "";
        }

        return Integer.toString(i);
    }

    private void loadSection(Model model, Config cfg, String sec) {
        int i = 1;
        while (true) {
            if (!loadAssertion(model, cfg, sec, sec + getKeySuffix(i))) {
                break;
            } else {
                i++;
            }
        }
    }

    /**
     * Helper function for loadModel and loadModelFromText
     *
     * @param cfg the configuration parser
     */
    private void loadSections(Config cfg) {
        loadSection(this, cfg, "r");
        loadSection(this, cfg, "p");
        loadSection(this, cfg, "e");
        loadSection(this, cfg, "m");

        loadSection(this, cfg, "g");
    }

    /**
     * SetLogger sets the model's logger.
     *
     * @param logger the logger to be set for the model.
     */
    public void setLogger(Logger logger) {
        for (Map<String, Assertion> astMap : model.values()) {
            for (Assertion ast : astMap.values()) {
                ast.setLogger(logger);
            }
        }
        model.put("logger", Collections.singletonMap("logger", new Assertion(logger)));
    }

    /**
     * NewModel creates an empty model.
     *
     * @return a new instance of the Model.
     */
    public static Model newModel() {
        Model model = new Model();
        model.setLogger(new DefaultLogger());
        return model;
    }

    /**
     * NewModelFromString creates a model from a string which contains model text.
     *
     * @param path the path of the model file.
     * @return the model loaded from file.
     */
    public static Model newModelFromFile(String path) {
        Model model = new Model();
        model.loadModel(path);
        return model;
    }

    /**
     * NewModelFromString creates a model from a string which contains model text.
     *
     * @param text the path of the file.
     * @return the model loaded from text.
     */
    public static Model newModelFromString(String text) {
        Model model = new Model();
        model.loadModelFromText(text);
        return model;
    }

    /**
     * loadModel loads the model from model CONF file.
     *
     * @param path the path of the model file.
     */
    public void loadModel(String path) {
        Config cfg = Config.newConfig(path);

        loadSections(cfg);
    }

    /**
     * loadModelFromText loads the model from the text.
     *
     * @param text the model text.
     */
    public void loadModelFromText(String text) {
        Config cfg = Config.newConfigFromText(text);

        loadSections(cfg);
    }

    /**
     * loadModelFromConfig loads the model from the configuration.
     *
     * @param cfg the model text.
     */
    public void loadModelFromConfig(Config cfg) {
        for (String s : sectionNameMap.keySet()) {
            loadSection(this, cfg, s);
        }
        List<String> ms = new ArrayList<>();
        for (String rs : requiredSections) {
            if (!hasSection(rs)) {
                ms.add(sectionNameMap.get(rs));
            }
        }
        if (!ms.isEmpty()) {
            throw new RuntimeException("missing required sections: " + String.join(",", ms));
        }
    }

    /**
     * hasSection checks if the section exists in the model.
     *
     * @param sec the section name to check, such as "p" or "g".
     * @return  whether the section exists in the model.
     */
    public boolean hasSection(String sec) {
        Map<String, Assertion> section = model.get(sec);
        return section != null;
    }

    /**
     * saveSectionToText saves the section to the text.
     *
     * @return the section text.
     */
    private String saveSectionToText(String sec) {
        StringBuilder res = new StringBuilder("[" + sectionNameMap.get(sec) + "]\n");

        Map<String, Assertion> section = model.get(sec);
        if (section == null) {
            return "";
        }

        for (Map.Entry<String, Assertion> entry : section.entrySet()) {
             res.append(String.format("%s = %s\n", entry.getKey(), entry.getValue().value.replace("_", ".")));
        }

        return res.toString();
    }

    /**
     * saveModelToText saves the model to the text.
     *
     * @return the model text.
     */
    public String saveModelToText() {
        StringBuilder res = new StringBuilder();

        res.append(saveSectionToText("r"));
        res.append("\n");
        res.append(saveSectionToText("p"));
        res.append("\n");

        String g = saveSectionToText("g");
        g = g.replace(".", "_");
        res.append(g);
        if (!"".equals(g)) {
            res.append("\n");
        }

        res.append(saveSectionToText("e"));
        res.append("\n");
        res.append(saveSectionToText("m"));

        return res.toString();
    }

    /**
     * printModel prints the model to the log.
     */
    public void printModel() {
        if (!Util.isLogPrintEnabled()) {
            return;
        }
        Util.logPrint("Model:");
        for (Map.Entry<String, Map<String, Assertion>> entry : model.entrySet()) {
            for (Map.Entry<String, Assertion> entry2 : entry.getValue().entrySet()) {
                Util.logPrintfInfo("{}.{}: {}", entry.getKey(), entry2.getKey(), entry2.getValue().value);
            }
        }
    }

    /**
     * sort policies by priority value
     */
    public void sortPoliciesByPriority() {
        if (!model.containsKey("p")) {
            return;
        }

        for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
            Assertion assertion = entry.getValue();
            int priorityIndex = assertion.priorityIndex;
            if (priorityIndex < 0) {
                continue;
            }
            assertion.policy.sort(Comparator.comparingInt(p -> Integer.parseInt(p.get(priorityIndex))));
            for (int i = 0; i < assertion.policy.size(); ++i) {
                assertion.policyIndex.put(Assertion.policyKey(assertion.policy.get(i)), i);
            }
        }
    }

    /**
     * sort policies by hieraichy map
     */
    public void sortPoliciesBySubjectHieraichy() {
        if (model.get("e") == null || model.get("p") == null || model.get("g") == null || model.get("g").get("g") == null) {
            return;
        }

        for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
            if (!"subjectPriority(p_eft) || deny".equals(effectForPolicyType(entry.getKey()))) {
                continue;
            }
            Map<String, Integer> subjectHierarchyMap = getSubjectHierarchyMap(model.get("g").get("g").policy);
            Assertion assertion = entry.getValue();
            domainIndex = -1;
            for(int i=0; i<assertion.tokens.length; i++){
                if(assertion.tokens[i].equals(assertion.key+"_dom")){
                    domainIndex = i;
                    break;
                }
            }
            Collections.sort(assertion.policy, (o1, o2)->{
                String domain1 = domainIndex!=-1 ? o1.get(domainIndex) : defaultDomain;
                String domain2 = domainIndex!=-1 ? o2.get(domainIndex) : defaultDomain;
                int priority1 = subjectHierarchyMap.getOrDefault(getNameWithDomain(domain1, o1.get(0)), 0);
                int priority2 = subjectHierarchyMap.getOrDefault(getNameWithDomain(domain2, o2.get(0)), 0);
                return priority2-priority1;
            });
            assertion.policyIndex.clear();
            for (int i = 0; i < assertion.policy.size(); ++i) {
                assertion.policyIndex.put(Assertion.policyKey(assertion.policy.get(i)), i);
            }
        }

    }

    // effectForPolicyType returns the effect of the e section that pairs with ptype by suffix (p2 -> e2),
    // falling back to the default e section.
    private String effectForPolicyType(String ptype) {
        Map<String, Assertion> effects = model.get("e");
        Assertion assertion = effects.get("e" + ptype.substring(1));
        if (assertion == null) {
            assertion = effects.get("e");
        }
        return assertion == null ? null : assertion.value;
    }

    public Map<String, Integer> getSubjectHierarchyMap(List<List<String>> policies) {
        Map<String, Integer> subjectHierarchyMap = new HashMap<>();
        Map<String, String> policyMap = new HashMap<>();
        String domain = defaultDomain;

        for(List<String> policy:policies) {
            if(policy.size()!=2) {
                domain = policy.get(2);
            }
            String child = getNameWithDomain(domain, policy.get(0));
            String parent = getNameWithDomain(domain, policy.get(1));
            policyMap.put(child, parent);
            if(!subjectHierarchyMap.containsKey(child)) {
                subjectHierarchyMap.put(child, 0);
            }
            if(!subjectHierarchyMap.containsKey(parent)) {
                subjectHierarchyMap.put(parent, 0);
            }
            subjectHierarchyMap.replace(child, 1);
        }
        List<String> set = new ArrayList<>();
        for (String key : subjectHierarchyMap.keySet()) {
            if (subjectHierarchyMap.get(key) != 0) set.add(key);
        }
        while (!set.isEmpty()){
            String child = set.get(0);
            findHierarchy(policyMap, subjectHierarchyMap, set, child);
        }
        return subjectHierarchyMap;
    }

    private void findHierarchy(Map<String, String> policyMap, Map<String, Integer> subjectHierarchyMap, List<String> set, String child) {
        set.remove(child);
        String parent = policyMap.get(child);
        if (set.contains(parent)) {
            findHierarchy(policyMap, subjectHierarchyMap, set, parent);
        }
        subjectHierarchyMap.replace(child, subjectHierarchyMap.get(parent)+10);
    }

    public String getNameWithDomain(String domain, String name) {
        return domain + defaultSeparator + name;
    }

    public enum PolicyOperations {
        POLICY_ADD,
        POLICY_REMOVE
    }

    public String toText() {
        Map<String, String> tokenPatterns = new HashMap<>();

        Pattern pPattern = Pattern.compile("^p_");
        Pattern rPattern = Pattern.compile("^r_");

        for (String ptype : new String[]{"r", "p"}) {
            for (String token : model.get(ptype).get(ptype).tokens) {
                String newToken = rPattern.matcher(pPattern.matcher(token).replaceAll("p.")).replaceAll("r.");
                tokenPatterns.put(token, newToken);
            }
        }

        if (model.get("e").get("e").value.contains("p_eft")) {
            tokenPatterns.put("p_eft", "p.eft");
        }

        StringBuilder s = new StringBuilder();
        writeString(s, "r", tokenPatterns);
        writeString(s, "p", tokenPatterns);

        if (model.containsKey("g")) {
            s.append("[role_definition]\n");
            for (String ptype : model.get("g").keySet()) {
                s.append(String.format("%s = %s\n", ptype, model.get("g").get(ptype).value));
            }
        }

        writeString(s, "e", tokenPatterns);
        writeString(s, "m", tokenPatterns);

        return s.toString();
    }

    private void writeString(StringBuilder s, String sec, Map<String, String> tokenPatterns) {
        s.append(String.format("[%s]\n", sectionNameMap.get(sec)));
        for (String ptype : model.get(sec).keySet()) {
            String value = model.get(sec).get(ptype).value;
            for (Map.Entry<String, String> entry : tokenPatterns.entrySet()) {
                value = value.replace(entry.getKey(), entry.getValue());
            }
            s.append(String.format("%s = %s\n", sec, value));
        }
    }
}
