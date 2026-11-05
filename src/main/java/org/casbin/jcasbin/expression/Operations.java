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

package org.casbin.jcasbin.expression;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

final class Operations {
    private static final int MAX_CACHED_PATTERNS = 1000;
    private static final Map<String, Pattern> PATTERNS = new ConcurrentHashMap<>();

    private Operations() {
    }

    static boolean toBoolean(Object value, String operator) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        throw new ExpressionException("value " + describe(value) + " cannot be used with '" + operator + "', it is not a boolean");
    }

    static boolean equal(Object left, Object right) {
        if (left == null || right == null) {
            return left == right;
        }
        if (left instanceof Number && right instanceof Number) {
            return compareNumbers((Number) left, (Number) right) == 0;
        }
        if (left instanceof Character) {
            left = left.toString();
        }
        if (right instanceof Character) {
            right = right.toString();
        }
        return Objects.equals(left, right);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    static int compare(Object left, Object right, String operator) {
        if (left instanceof Number && right instanceof Number) {
            return compareNumbers((Number) left, (Number) right);
        }
        if (isText(left) && isText(right)) {
            return left.toString().compareTo(right.toString());
        }
        if (left instanceof Comparable && right != null && left.getClass() == right.getClass()) {
            return ((Comparable) left).compareTo(right);
        }
        throw new ExpressionException("values " + describe(left) + " and " + describe(right) + " cannot be compared with '" + operator + "'");
    }

    static boolean in(Object needle, Object haystack) {
        if (haystack instanceof Collection) {
            for (Object item : (Collection<?>) haystack) {
                if (equal(needle, item)) {
                    return true;
                }
            }
            return false;
        }
        if (haystack != null && haystack.getClass().isArray()) {
            int length = Array.getLength(haystack);
            for (int i = 0; i < length; i++) {
                if (equal(needle, Array.get(haystack, i))) {
                    return true;
                }
            }
            return false;
        }
        throw new ExpressionException("the right side of 'in' must be an array or a collection, got " + describe(haystack));
    }

    static boolean regexMatch(Object text, Object pattern) {
        if (!isText(text) || !isText(pattern)) {
            throw new ExpressionException("'=~' needs a string and a pattern, got " + describe(text) + " and " + describe(pattern));
        }
        String regex = pattern.toString();
        Pattern compiled = PATTERNS.get(regex);
        if (compiled == null) {
            try {
                compiled = Pattern.compile(regex);
            } catch (PatternSyntaxException e) {
                throw new ExpressionException("invalid regular expression '" + regex + "'", e);
            }
            if (PATTERNS.size() >= MAX_CACHED_PATTERNS) {
                PATTERNS.clear();
            }
            PATTERNS.put(regex, compiled);
        }
        return compiled.matcher(text.toString()).find();
    }

    static Object arithmetic(String operator, Object left, Object right) {
        if ("+".equals(operator) && (isText(left) || isText(right))) {
            return String.valueOf(left) + right;
        }
        if (!(left instanceof Number) || !(right instanceof Number)) {
            throw new ExpressionException("values " + describe(left) + " and " + describe(right) + " cannot be used with '" + operator + "', they are not numbers");
        }
        Number a = (Number) left;
        Number b = (Number) right;
        // Division is always floating point, as in Go.
        if (isIntegral(a) && isIntegral(b) && !"/".equals(operator)) {
            long x = a.longValue();
            long y = b.longValue();
            switch (operator) {
                case "+": return x + y;
                case "-": return x - y;
                case "*": return x * y;
                case "%":
                    return y == 0 ? (Object) Double.NaN : (Object) (x % y);
                case "**":
                    if (y >= 0) {
                        double power = Math.pow(x, y);
                        if (Math.abs(power) < 0x1p63) {
                            return (long) power;
                        }
                        return power;
                    }
                    return Math.pow(x, y);
                case "&": return x & y;
                case "|": return x | y;
                case "^": return x ^ y;
                case "<<": return x << y;
                case ">>": return x >> y;
                default:
                    break;
            }
        } else {
            double x = a.doubleValue();
            double y = b.doubleValue();
            switch (operator) {
                case "+": return x + y;
                case "-": return x - y;
                case "*": return x * y;
                case "/": return x / y;
                case "%": return x % y;
                case "**": return Math.pow(x, y);
                case "&": return a.longValue() & b.longValue();
                case "|": return a.longValue() | b.longValue();
                case "^": return a.longValue() ^ b.longValue();
                case "<<": return a.longValue() << b.longValue();
                case ">>": return a.longValue() >> b.longValue();
                default:
                    break;
            }
        }
        throw new ExpressionException("unknown operator '" + operator + "'");
    }

    static Object negate(Object value) {
        if (value instanceof Number) {
            Number n = (Number) value;
            return isIntegral(n) ? (Object) (-n.longValue()) : (Object) (-n.doubleValue());
        }
        throw new ExpressionException("value " + describe(value) + " cannot be negated, it is not a number");
    }

    static Object bitwiseNot(Object value) {
        if (value instanceof Number) {
            return ~((Number) value).longValue();
        }
        throw new ExpressionException("value " + describe(value) + " cannot be used with '~', it is not a number");
    }

    private static int compareNumbers(Number a, Number b) {
        if (isIntegral(a) && isIntegral(b)) {
            return Long.compare(a.longValue(), b.longValue());
        }
        if (a instanceof BigDecimal || b instanceof BigDecimal || a instanceof BigInteger || b instanceof BigInteger) {
            return new BigDecimal(a.toString()).compareTo(new BigDecimal(b.toString()));
        }
        return Double.compare(a.doubleValue(), b.doubleValue());
    }

    private static boolean isIntegral(Number n) {
        return n instanceof Long || n instanceof Integer || n instanceof Short || n instanceof Byte;
    }

    private static boolean isText(Object value) {
        return value instanceof String || value instanceof Character;
    }

    static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return "'" + value + "' (String)";
        }
        return value + " (" + value.getClass().getSimpleName() + ")";
    }
}
