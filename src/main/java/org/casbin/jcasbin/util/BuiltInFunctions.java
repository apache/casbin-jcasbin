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

package org.casbin.jcasbin.util;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.casbin.jcasbin.expression.Expression;
import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.rbac.ConditionalRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.function.FunctionArgs;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class BuiltInFunctions {

    private static final Pattern KEY_MATCH2_PATTERN = Pattern.compile(":[^/]+");
    private static final Pattern KEY_MATCH3_PATTERN = Pattern.compile("\\{[^/]+\\}");
    private static final Pattern KEY_MATCH5_PATTERN = Pattern.compile("\\{[^/]+\\}");
    private static final int MAX_EVAL_EXPRESSIONS = 10000;
    private static final Map<String, Expression> EVAL_EXPRESSIONS = new ConcurrentHashMap<>();

    /**
     * validate the variadic string parameter size
     *
     * @param args         the expected number of arguments.
     * @param expectedLen  the variadic string arguments to validate.
     */
    public static void validateVariadicStringArgs(int expectedLen, String... args) throws IllegalArgumentException {
        int length = args!=null?args.length:0;
        if (length != expectedLen) {
            throw new IllegalArgumentException(String.format("Expected %d arguments, but got %d", expectedLen, args.length));
        }
    }

    /**
     * keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch(String key1, String key2) {
        int i = key2.indexOf('*');
        if (i == -1) {
            return key1.equals(key2);
        }

        if (key1.length() > i) {
            return key1.substring(0, i).equals(key2.substring(0, i));
        }
        return key1.equals(key2.substring(0, i));
    }

    /**
     * keyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch2(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");
        key2 = KEY_MATCH2_PATTERN.matcher(key2).replaceAll("[^/]+");
        key2 = key2.replaceAll("\\{([^/]+)\\}", "([^/]+)");
        if(Objects.equals(key2, "*")) {
            key2 = "(.*)";
        }
        return regexMatch(key1, "^" + key2 + "$");
    }

    /**
     * keyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch3(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");
        key2 = "^" + KEY_MATCH3_PATTERN.matcher(key2).replaceAll("[^/]+") + "$";
        try {
            return regexMatch(key1, key2);
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *. Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
     *
     * <pre>
     * "/parent/123/child/123" matches "/parent/{id}/child/{id}"
     * "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
     * But KeyMatch3 will match both.
     * </pre>
     *
     * Attention: key1 cannot contain English commas.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch4(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");

        ArrayList<String> tokens = new ArrayList<>();

        Pattern p = Pattern.compile("\\{[^{}]*\\}");
        Matcher m = p.matcher(key2);
        StringBuffer sb = new StringBuffer();
        while(m.find()) {
            String group = m.group();
            tokens.add(group);
            if(group.contains("/")) {
                group = group.replace("{", "\\{")
                            .replace("}", "\\}")
                            .replace("/", "\\/");
                m.appendReplacement(sb, Matcher.quoteReplacement(group));
            } else {
                m.appendReplacement(sb, "([^/]+)");
            }
        }
        m.appendTail(sb);
        key2 = sb.toString();

        p = Pattern.compile("^" + key2 + "$");
        m = p.matcher(key1);

        ArrayList<String> matches = new ArrayList<>();
        if (m.find()) {
            for (int i = 0; i <=  m.groupCount(); i++) {
                matches.add(m.group(i));
            }
        }

        if(matches.isEmpty()) {
            return false;
        }

        matches.remove(0);

        if(tokens.size() != matches.size()) {
            throw new RuntimeException("KeyMatch4: number of tokens is not equal to number of values");
        }

        Map<String ,String> values = new HashMap<>();

        for (int key = 0; key < tokens.size(); ++key) {
            String token = tokens.get(key);
            if(!values.containsKey(token)) {
                values.put(token, matches.get(key));
            }
            if(!values.get(token).equals(matches.get(key))) {
                return false;
            }
        }

        return true;
    }

    /**
     * KeyMatch5 determines whether key1 matches the pattern of key2 and ignores the parameters in key2.
     *
     * <pre>
     * For example, "/foo/bar?status=1&amp;type=2" matches "/foo/bar"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch5(String key1, String key2) {
        int i = key1.indexOf('?');
        if (i != -1) {
            key1 = key1.substring(0,i);
        }

        key2 = key2.replace("/*", "/.*");
        key2 = KEY_MATCH5_PATTERN.matcher(key2).replaceAll("[^/]+");

        return regexMatch(key1, "^" + key2 + "$");
    }

    /**
     * KeyGet returns the matched part. For example, "/foo/bar/foo" matches "/foo/*", "bar/foo" will been returned
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return the matched part.
     */
    public static String keyGetFunc(String key1, String key2) {
        int index = key2.indexOf('*');
        if (index == -1) {
            return "";
        }
        if (key1.length() > index) {
            if (key1.substring(0, index).equals(key2.substring(0, index))) {
                return key1.substring(index);
            }
        }
        return "";
    }

    /**
     * KeyGet2 returns value matched pattern.For example, "/resource1" matches "/:resource", if the pathVar == "resource", then "resource1" will be returned.
     *
     * @param key1    the first argument.
     * @param key2    the second argument.
     * @param pathVar the name of the variable to retrieve from the matched pattern.
     * @return the matched part.
     */
    public static String keyGet2Func(String key1, String key2, String pathVar) {
        key2 = key2.replace("/*", "/.*");
        String regexp = ":[^/]+";
        Pattern re = Pattern.compile(regexp);
        Matcher keys = re.matcher(key2);
        List<String> keysList = new ArrayList<>();
        while (keys.find()) {
            keysList.add(keys.group());
        }
        key2 = keys.replaceAll("([^/]+)");
        key2 = "^" + key2 + "$";
        Pattern re2 = Pattern.compile(key2);
        Matcher values = re2.matcher(key1);
        List<String> valuesList = new ArrayList<>();
        while (values.find()) {
            for (int i = 0; i <= values.groupCount(); i++) {
                valuesList.add(values.group(i));
            }
        }
        if (valuesList.isEmpty()) {
            return "";
        }
        for (int i = 0; i < keysList.size(); i++) {
            if (pathVar.equals(keysList.get(i).substring(1))) {
                return valuesList.get(i + 1);
            }
        }
        return "";
    }

    /**
     * KeyGet3 returns value matched pattern. For example, "/resource1" matches "/{resource}", if the pathVar == "resource", then "resource1" will be returned.
     * This is similar with KeyGet2(), except using "/proxy/{id}" instead of "/proxy/:id".
     *
     * @param key1    the first argument.
     * @param key2    the second argument.
     * @param pathVar the name of the variable to retrieve from the matched pattern.
     * @return the matched part.
     */
    public static String keyGet3Func(String key1, String key2, String pathVar) {
        key2 = key2.replace("/*", "/.*");
        String regexp = "\\{[^/]+?\\}";
        Pattern re = Pattern.compile(regexp);
        Matcher keys = re.matcher(key2);
        List<String> keysList = new ArrayList<>();
        while (keys.find()) {
            keysList.add(keys.group());
        }
        key2 = re.matcher(key2).replaceAll("([^/]+?)");
        // Escape { and } for Java regex compatibility since { is treated as repetition quantifier
        key2 = key2.replace("{", "\\{").replace("}", "\\}");
        key2 = "^" + key2 + "$";
        Pattern re2 = Pattern.compile(key2);
        Matcher values = re2.matcher(key1);
        if (!values.find()) {
            return "";
        }
        for (int i = 0; i < keysList.size(); i++) {
            if (pathVar.equals(keysList.get(i).substring(1, keysList.get(i).length() - 1))) {
                return values.group(i + 1);
            }
        }
        return "";
    }

    /**
     * regexMatch determines whether key1 matches the pattern of key2 in regular expression.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean regexMatch(String key1, String key2) {
        return Pattern.compile(key2).matcher(key1).find();
    }

    /**
     * ipMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be
     * an IP address or a CIDR pattern. For example, "192.168.2.123" matches "192.168.2.0/24"
     *
     * @param ip1 the first argument.
     * @param ip2 the second argument.
     * @return whether ip1 matches ip2.
     */
    public static boolean ipMatch(String ip1, String ip2) {
        IPAddressString ipas1 = new IPAddressString(ip1);
        try {
            ipas1.validateIPv4();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");
        }

        IPAddressString ipas2 = new IPAddressString(ip2);
        try {
            ipas2.validate();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("invalid argument: ip2 in IPMatch() function is neither an IP address nor a CIDR.");
        }

        if (ipas1.equals(ipas2)) {
            return true;
        }

        IPAddress ipa1;
        IPAddress ipa2;
        try {
            ipa1 = ipas1.toAddress();
            ipa2 = ipas2.toAddress();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("invalid argument: ip1 or ip2 in IPMatch() function is not an IP address.");
        }

        Integer prefix = ipa2.getNetworkPrefixLength();
        IPAddress mask = ipa2.getNetwork().getNetworkMask(prefix, false);
        return ipa1.mask(mask).equals(ipa2.mask(mask));
    }

    /**
     * globMatch determines whether key1 matches the pattern of key2 in glob expression.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean globMatch(String key1, String key2) {
        return Pattern.matches(Glob.toRegexPattern(key2), key1);
    }

    /**
     * allMatch determines whether key1 matches the pattern of key2 , key2 can contain a *.
     *
     * <pre>
     * For example, "*" matches everything
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean allMatch(String key1, String key2) {
        if ("*".equals(key2)) {
            return true;
        }

        return key1.equals(key2);
    }


    public static class GenerateGFunctionClass {
        /**
         * generateGFunction is the factory method of the g(_, _) function.
         *
         * @param name the name of the g(_, _) function, can be "g", "g2", ..
         * @param rm   the role manager used by the function.
         * @return the function.
         */
        public static ExpressionFunction generateGFunction(String name, RoleManager rm) {
            return generateGFunction(name, rm, new ConcurrentHashMap<>());
        }

        /**
         * generateGFunction is the factory method of the g(_, _) function.
         *
         * @param name         the name of the g(_, _) function, can be "g", "g2", ..
         * @param rm           the role manager used by the function.
         * @param memorizedMap the cache of g(_, _) results owned by the caller, key: name such as g, g2.
         * @return the function.
         */
        public static ExpressionFunction generateGFunction(String name, RoleManager rm, Map<String, Map<String, Boolean>> memorizedMap) {
            memorizedMap.put(name, new ConcurrentHashMap<>());

            return args -> {
                Map<String, Boolean> memorized = memorizedMap.get(name);
                int len = args.length;
                if (len < 2) {
                    return false;
                }
                String name1 = FunctionArgs.getString(args, 0);
                String name2 = FunctionArgs.getString(args, 1);

                String key = gFunctionCacheKey(args);
                Boolean value = memorized.get(key);
                if (value != null) {
                    return value;
                }

                if (rm == null) {
                    value = name1.equals(name2);
                } else if (len == 2) {
                    value = rm.hasLink(name1, name2);
                } else {
                    String domain = FunctionArgs.getString(args, 2);
                    value = rm.hasLink(name1, name2, domain);
                }
                memorized.put(key, value);
                return value;
            };
        }
    }

    public static class GenerateConditionalGFunctionClass {
        /**
         * GenerateConditionalGFunction is the factory method of the g(_, _[, _]) function with conditions.
         *
         * @param name    the name of the g(_, _) function, can be "g", "g2", ..
         * @param condRm  the conditional role manager used by the function.
         * @return the function.
         */
        public static ExpressionFunction generateConditionalGFunction(String name, ConditionalRoleManager condRm) {
            return generateConditionalGFunction(name, condRm, new ConcurrentHashMap<>());
        }

        /**
         * GenerateConditionalGFunction is the factory method of the g(_, _[, _]) function with conditions.
         *
         * @param name         the name of the g(_, _) function, can be "g", "g2", ..
         * @param condRm       the conditional role manager used by the function.
         * @param memorizedMap the cache of g(_, _) results owned by the caller, key: name such as g, g2.
         * @return the function.
         */
        public static ExpressionFunction generateConditionalGFunction(String name, ConditionalRoleManager condRm, Map<String, Map<String, Boolean>> memorizedMap) {
            memorizedMap.put(name, new ConcurrentHashMap<>());

            return args -> {
                Map<String, Boolean> memorized = memorizedMap.get(name);
                int len = args.length;
                if (len < 2) {
                    return false;
                }
                String name1 = FunctionArgs.getString(args, 0);
                String name2 = FunctionArgs.getString(args, 1);

                String key = gFunctionCacheKey(args);
                Boolean value = memorized.get(key);
                if (value != null) {
                    return value;
                }

                if (condRm == null) {
                    value = name1.equals(name2);
                } else if (len == 2) {
                    value = condRm.hasLink(name1, name2);
                } else {
                    String domain = FunctionArgs.getString(args, 2);
                    value = condRm.hasLink(name1, name2, domain);
                }
                memorized.put(key, value);
                return value;
            };
        }
    }

    private static String gFunctionCacheKey(Object[] args) {
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < args.length; i++) {
            key.append(';').append(FunctionArgs.getString(args, i));
        }
        return key.toString();
    }

    /**
     * eval calculates the stringified boolean expression and return its result.
     *
     * @param eval      the stringified boolean expression.
     * @param env       the key-value pair of the parameters in the expression.
     * @param functions the built-in functions and custom functions the expression can call,
     *                  null means only the built-in functions.
     * @return the result of the eval, false if the expression is invalid or fails.
     */
    public static boolean eval(String eval, Map<String, Object> env, Map<String, ? extends ExpressionFunction> functions) {
        if (functions == null) {
            functions = FunctionMap.loadFunctionMap().fm;
        }
        try {
            Expression expression = EVAL_EXPRESSIONS.get(eval);
            if (expression == null) {
                expression = Expression.compile(eval);
                if (EVAL_EXPRESSIONS.size() >= MAX_EVAL_EXPRESSIONS) {
                    EVAL_EXPRESSIONS.clear();
                }
                EVAL_EXPRESSIONS.put(eval, expression);
            }
            Object res = expression.evaluate(env, functions);
            return res instanceof Boolean && (Boolean) res;
        } catch (Exception e) {
            Util.logPrintfWarn("Execute 'eval' function error, nested exception is: {}", e.getMessage());
            return false;
        }
    }

    // builtin LinkConditionFunc

    /**
     * timeMatchFunc is the wrapper for TimeMatch.
     *
     * @param args the arguments for the time match function.
     * @return whether the time matches the pattern.
     */
    public static boolean timeMatchFunc(String... args) {
        try {
            validateVariadicStringArgs(2, args);
            return timeMatch(args[0], args[1]);
        } catch (IllegalArgumentException e) {
            System.err.println("TimeMatch: " + e.getMessage());
            return false;
        }
    }

    /**
     * TimeMatch determines whether the current time is between startTime and endTime.
     * You can use "_" to indicate that the parameter is ignored
     *
     * @param startTime the start time as a string in the format "yyyy-MM-dd HH:mm:ss". Use "_" to ignore the start time.
     * @param endTime the end time as a string in the format "yyyy-MM-dd HH:mm:ss". Use "_" to ignore the end time.
     * @return whether the current time is between startTime and endTime
     */
    public static boolean timeMatch(String startTime, String endTime) {
        LocalDateTime now = LocalDateTime.now();

        if (!startTime.equals("_")) {
            LocalDateTime start;
            // special process for "0000" year,LocalDateTime range is 1-999999999
            if (startTime.startsWith("0000")){
                start = LocalDateTime.MIN;
            }else {
                start = LocalDateTime.parse(startTime, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            }
            if (!now.isAfter(start)) {
                return false;
            }
        }

        if (!endTime.equals("_")) {

            LocalDateTime end;
            // special process for "0000" year,LocalDateTime range is 1-999999999
            if (endTime.startsWith("0000")){
                end = LocalDateTime.MIN;
            }else {
                end = LocalDateTime.parse(endTime, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            }
            if (!now.isBefore(end)) {
                return false;
            }
        }

        return true;
    }
}
