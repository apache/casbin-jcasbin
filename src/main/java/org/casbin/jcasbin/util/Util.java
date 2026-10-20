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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Util {
    public static boolean enableLog = true;
    private static Pattern evalReg = Pattern.compile("\\beval\\(([^),]*)\\)");

    private static final Pattern IN_SYNTAX_PATTERN = Pattern.compile("([^\\s]+?) +in +(\\([^)]*\\)|\\S+)");

    private static Pattern escapeAssertionRegex = Pattern.compile("\\b(r|p)[0-9]*\\.");

    private static Logger LOGGER = LoggerFactory.getLogger("org.casbin.jcasbin");

    private static final String md5AlgorithmName = "MD5";

    /**
     * isLogPrintEnabled checks if {@code logPrint} or {@code logPrintfInfo} are enabled.
     *
     * @return {@code true} if INFO logs are enabled.
     */
    public static boolean isLogPrintEnabled() {
        return enableLog && LOGGER.isInfoEnabled();
    }

    /**
     * logPrint prints the log.
     *
     * @param v the log.
     */
    public static void logPrint(String v) {
        if (enableLog) {
            LOGGER.info(v);
        }
    }

    /**
     * logPrintfInfo prints the log with the SLF4J format.
     *
     * @param format the format of the log.
     * @param v      the log.
     */
    public static void logPrintfInfo(String format, Object... v) {
        if (enableLog) {
            LOGGER.info(format, v);
        }
    }

    /**
     * logPrintf prints the log with the format.
     *
     * @param format the format of the log.
     * @param v      the log.
     */
    @Deprecated
    public static void logPrintf(String format, String... v) {
        if (enableLog) {
            String tmp = String.format(format, (Object[]) v);
            LOGGER.info(tmp);
        }
    }

    /**
     * logPrintf prints the log with the format as a warning.
     *
     * @param format the format of the log.
     * @param v      the log.
     */
    public static void logPrintfWarn(String format, Object... v) {
        if (enableLog) {
            LOGGER.warn(format, v);
        }
    }

    /**
     * logPrintf prints the log with the format as an error.
     *
     * @param format the format of the log.
     * @param v      the log.
     */
    public static void logPrintfError(String format, Object... v) {
        if (enableLog) {
            LOGGER.error(format, v);
        }
    }

    /**
     * logPrintf prints the log with the format as an error.
     *
     * @param message the message accompanying the exception
     * @param t       the exception (throwable) to log
     */
    public static void logPrintfError(String message, Throwable t) {
        if (enableLog) {
            LOGGER.error(message, t);
        }
    }

    /**
     * logEnforce prints the log of Enforce.
     *
     * @param request the Enforce request.
     * @param result  the Enforce result.
     * @param explain to explain enforcement by matched rules.
     */
    public static void logEnforce(Object[] request, boolean result, List<String> explain) {
        if (enableLog) {
            LOGGER.info("Request: " + Arrays.toString(request) + " ---> " + result);
            if (explain != null) {
                LOGGER.info("Hit Policy: " + explain);
            }
        }
    }

    /**
     * escapeAssertion escapes the dots in the assertion, because the expression
     * evaluation doesn't support such variable names. Quoted string literals
     * are kept as they are.
     *
     * @param s the value of the matcher and effect assertions.
     * @return the escaped value.
     */
    public static String escapeAssertion(String s) {
        StringBuilder sb = new StringBuilder();
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            char quote = s.charAt(i);
            if (quote != '"' && quote != '\'') {
                continue;
            }
            int end = i + 1;
            while (end < s.length() && s.charAt(end) != quote) {
                if (s.charAt(end) == '\\') {
                    end++;
                }
                end++;
            }
            end = Math.min(end + 1, s.length());
            sb.append(escapeAssertionUnquoted(s.substring(start, i)));
            sb.append(s, i, end);
            start = end;
            i = end - 1;
        }
        sb.append(escapeAssertionUnquoted(s.substring(start)));
        return sb.toString();
    }

    private static String escapeAssertionUnquoted(String s) {
        Matcher m = escapeAssertionRegex.matcher(s);
        StringBuffer sb = new StringBuffer();

        while (m.find()) {
            m.appendReplacement(sb, m.group().replace(".", "_"));
        }

        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * convertInSyntax Convert 'in' to 'include' to fit aviatorscript,because
     * aviatorscript don't support native 'in' syntax
     *
     * @param expString the value of the matcher
     * @return the 'include' expression.
     */
    public static String convertInSyntax(String expString) {
        if (expString.contains(" in ")) {
            Matcher matcher = IN_SYNTAX_PATTERN.matcher(expString);
            if (matcher.find()) {
                return replaceInSyntaxWithInclude(matcher);
            }
        }

        return expString;
    }

    private static String replaceInSyntaxWithInclude(Matcher matcher) {
        StringBuffer sb = new StringBuffer();
        do {
            String leftOperand = matcher.group(1);
            String rightOperand = matcher.group(2);
            
            // If right operand is a parenthesized expression with commas (tuple literal),
            // convert to tuple() function. Otherwise, keep parentheses as-is for grouping.
            if (rightOperand.startsWith("(") && rightOperand.endsWith(")") && rightOperand.contains(",")) {
                rightOperand = "tuple" + rightOperand;
            }
            
            matcher.appendReplacement(sb, Matcher.quoteReplacement("include(" + rightOperand + ", " + leftOperand + ")"));
        } while (matcher.find());
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * removeComments removes the comments starting with # in the text.
     *
     * @param s a line in the model.
     * @return the line without comments.
     */
    public static String removeComments(String s) {
        int pos = s.indexOf("#");
        if (pos == -1) {
            return s;
        }
        return s.substring(0, pos).trim();
    }

    /**
     * arrayEquals determines whether two string arrays are identical.
     *
     * @param a the first array.
     * @param b the second array.
     * @return whether a equals to b.
     */
    public static boolean arrayEquals(List<String> a, List<String> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
        if (a.size() != b.size()) {
            return false;
        }

        for (int i = 0; i < a.size(); i++) {
            if (!a.get(i).equals(b.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * array2DEquals determines whether two 2-dimensional string arrays are
     * identical.
     *
     * @param a the first 2-dimensional array.
     * @param b the second 2-dimensional array.
     * @return whether a equals to b.
     */
    public static boolean array2DEquals(List<List<String>> a, List<List<String>> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
        if (a.size() != b.size()) {
            return false;
        }

        for (int i = 0; i < a.size(); i++) {
            if (!arrayEquals(a.get(i), b.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * arrayRemoveDuplicates removes any duplicated elements in a string array
     * preserving the order.
     *
     * @param s the array.
     * @return the array without duplicates.
     */
    public static List<String> arrayRemoveDuplicates(List<String> s) {
        Set<String> set = new LinkedHashSet<>(s);
        return new ArrayList<String>(set);
    }

    /**
     * arrayToString gets a printable string for a string array.
     *
     * @param s the array.
     * @return the string joined by the array elements.
     */
    public static String arrayToString(List<String> s) {
        return String.join(", ", s);
    }

    /**
     * paramsToString gets a printable string for variable number of parameters.
     *
     * @param s the parameters.
     * @return the string joined by the parameters.
     */
    public static String paramsToString(String[] s) {
        return String.join(", ", s);
    }

    /**
     * splitCommaDelimited splits a comma-delimited string according to the default
     * processing method of the CSV file
     * into a string array. It assumes that any number of whitespace might exist
     * before or after the token and that tokens do not include
     * whitespace as part of their value unless they are enclosed by double
     * quotes.
     *
     * @param s the string.
     * @return the array with the string tokens.
     */
    public static String[] splitCommaDelimited(String s) {
        String[] records = null;
        if (s != null) {
            try {
                CSVFormat csvFormat = CSVFormat.Builder.create().setIgnoreSurroundingSpaces(true).build();
                CSVParser csvParser = csvFormat.parse(new StringReader(s));
                List<CSVRecord> csvRecords = csvParser.getRecords();
                records = new String[csvRecords.get(0).size()];
                for (int i = 0; i < csvRecords.get(0).size(); i++) {
                    records[i] = csvRecords.get(0).get(i).trim();
                }
            } catch (IOException e) {
                Util.logPrintfError("CSV parser failed to parse this line: " + s, e);
            }
        }
        return records;
    }

    /**
     * setEquals determines whether two string sets are identical.
     *
     * @param a the first set.
     * @param b the second set.
     * @return whether a equals to b.
     */
    public static boolean setEquals(List<String> a, List<String> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
        if (a.size() != b.size()) {
            return false;
        }

        Collections.sort(a);
        Collections.sort(b);

        for (int i = 0; i < a.size(); i++) {
            if (!a.get(i).equals(b.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static boolean hasEval(String exp) {
        return evalReg.matcher(exp).matches();
    }

    public static String replaceEval(String s, String replacement) {
        return evalReg.matcher(s).replaceAll("(" + replacement + ")");
    }

    public static String md5(String data) {
        return new String(getDigest(md5AlgorithmName).digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Helper method to check if a string is a valid JSON
     *
     * @param str the string to be checked.
     * @return whether the string is a valid
     */
    public static boolean isJsonString(String str) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.readTree(str);
            return true;
        } catch (JsonProcessingException e) {
            return false;
        }
    }

    /**
     * setSubtract returns the elements in {@code a} that aren't in {@code b}.
     * Preserves order from {@code a}.
     */
    public static List<String> setSubtract(List<String> a, List<String> b) {
        Set<String> bSet = new HashSet<>(b);
        List<String> result = new ArrayList<>();
        for (String item : a) {
            if (!bSet.contains(item)) {
                result.add(item);
            }
        }
        return result;
    }
}
