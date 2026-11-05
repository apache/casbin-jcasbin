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

import org.casbin.jcasbin.expression.Expression;
import org.casbin.jcasbin.expression.ExpressionException;
import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class ExpressionTest {
    public static class Subject {
        public String Department = "dev";
        private final String name;
        private final int age;
        private final boolean admin;

        Subject(String name, int age, boolean admin) {
            this.name = name;
            this.age = age;
            this.admin = admin;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }

        public boolean isAdmin() {
            return admin;
        }

        public void delete() {
            throw new IllegalStateException("must not be called");
        }
    }

    private static Object eval(String expression, Map<String, Object> variables) {
        return Expression.compile(expression).evaluate(variables, Collections.<String, ExpressionFunction>emptyMap());
    }

    private static Object eval(String expression) {
        return eval(expression, Collections.emptyMap());
    }

    private static Map<String, Object> vars(Object... pairs) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], pairs[i + 1]);
        }
        return m;
    }

    @Test
    public void testLiterals() {
        assertEquals(eval("'a\\'b'"), "a'b");
        assertEquals(eval("\"x\\ty\""), "x\ty");
        assertEquals(eval("'^/foo\\d+$'"), "^/foo\\d+$");
        assertEquals(eval("42"), 42L);
        assertEquals(eval("1.5"), 1.5);
        assertEquals(eval("true"), true);
        assertNull(eval("nil"));
        assertEquals(eval("('a', 'b')"), Arrays.asList("a", "b"));
        assertEquals(eval("['a']"), Collections.singletonList("a"));
        assertEquals(eval("()"), Collections.emptyList());
    }

    @Test
    public void testArithmetic() {
        assertEquals(eval("1 + 2 * 3"), 7L);
        assertEquals(eval("(1 + 2) * 3"), 9L);
        assertEquals(eval("10 - 4 - 3"), 3L);
        assertEquals(eval("10 / 4"), 2.5);
        assertEquals(eval("10 / 5"), 2.0);
        assertEquals(eval("10 / 4.0"), 2.5);
        assertEquals(eval("7 % 3"), 1L);
        // Same as Go: ** is left-associative and binds looser than unary minus.
        assertEquals(eval("2 ** 3 ** 2"), 64L);
        assertEquals(eval("-2 ** 2"), 4L);
        assertEquals(eval("'a' + 1"), "a1");
        assertEquals(eval("1 / 0"), Double.POSITIVE_INFINITY);
        assertThrows(ExpressionException.class, () -> eval("'a' - 1"));
    }

    @Test
    public void testPrecedence() {
        // Same as Go: & before ^ before |, and all of them before comparisons.
        assertEquals(eval("r_bits | 2 & 4", vars("r_bits", 1L)), 1L);
        assertEquals(eval("1 ^ 3 & 1"), 0L);
        assertEquals(eval("5 & 4 == 4"), true);
        assertEquals(eval("true || false && false"), true);
        assertEquals(eval("1 + 1 == 2 && 'a' < 'b'"), true);
        // 'in' binds like ==, so the guard before it still applies.
        assertEquals(eval("r_sub == 'bob' && r_public in (false)", vars("r_sub", "alice", "r_public", false)), false);
        assertEquals(eval("r_age > 18 ? 'adult' : 'minor'", vars("r_age", 20)), "adult");
        assertEquals(eval("r_name ?? 'anonymous'"), "anonymous");
    }

    @Test
    public void testComparison() {
        assertEquals(eval("r_age >= 18", vars("r_age", 18)), true);
        assertEquals(eval("r_age == 18", vars("r_age", 18)), true);
        assertEquals(eval("r_age == 18.0", vars("r_age", 18)), true);
        assertEquals(eval("r_score < 1.5", vars("r_score", 1.25f)), true);
        assertEquals(eval("'1' == 1"), false);
        assertEquals(eval("r_x == nil"), true);
        assertEquals(eval("r_x != 'a'"), true);
        assertEquals(eval("'abc' < 'abd'"), true);
        assertThrows(ExpressionException.class, () -> eval("'a' < 1"));
        assertThrows(ExpressionException.class, () -> eval("r_x < 1"));
    }

    @Test
    public void testIn() {
        assertEquals(eval("r_obj in ('data2', 'data3')", vars("r_obj", "data3")), true);
        assertEquals(eval("r_obj in ['data2', 'data3']", vars("r_obj", "data1")), false);
        assertEquals(eval("'bob' in r_admins", vars("r_admins", Arrays.asList("alice", "bob"))), true);
        assertEquals(eval("2 in r_ids", vars("r_ids", new int[]{1, 2})), true);
        assertEquals(eval("'x' in r_ids", vars("r_ids", new String[]{"y"})), false);
        assertEquals(eval("!('a' in ('b'))"), true);
        assertThrows(ExpressionException.class, () -> eval("'a' in 'abc'"));
    }

    @Test
    public void testRegex() {
        assertEquals(eval("r_path =~ '^/api/v[0-9]+/'", vars("r_path", "/api/v2/users")), true);
        assertEquals(eval("r_path !~ 'admin'", vars("r_path", "/api/v2/users")), true);
        assertThrows(ExpressionException.class, () -> eval("'a' =~ '('"));
    }

    @Test
    public void testProperties() {
        Subject alice = new Subject("alice", 20, true);
        Map<String, Object> v = vars("r_sub", alice, "r_obj", vars("Owner", "alice", "Meta", vars("level", 3)));
        assertEquals(eval("r_sub.name", v), "alice");
        assertEquals(eval("r_sub.Name", v), "alice");
        assertEquals(eval("r_sub.age > 18", v), true);
        assertEquals(eval("r_sub.admin", v), true);
        assertEquals(eval("r_sub.Department", v), "dev");
        assertEquals(eval("r_sub.name == r_obj.Owner", v), true);
        assertEquals(eval("r_obj.Meta.level >= 3", v), true);
        assertNull(eval("r_obj.Missing", v));
        assertNull(eval("r_none.name", v));
        assertThrows(ExpressionException.class, () -> eval("r_sub.class", v));
        assertThrows(ExpressionException.class, () -> eval("r_sub.delete", v));
        assertThrows(ExpressionException.class, () -> eval("r_sub.missing", v));
    }

    @Test
    public void testFunctions() {
        Map<String, ExpressionFunction> functions = new HashMap<>();
        functions.put("concat", args -> "" + args[0] + args[1]);
        Expression expression = Expression.compile("concat(r_sub, 'x') == 'ax' && concat('(', ')') == '()'");
        assertEquals(expression.evaluate(vars("r_sub", "a"), functions), true);
        assertThrows(ExpressionException.class, () -> eval("unknown(1)"));
    }

    @Test
    public void testShortCircuit() {
        Map<String, ExpressionFunction> functions = new HashMap<>();
        functions.put("fail", args -> {
            throw new IllegalStateException("must not be called");
        });
        assertEquals(Expression.compile("false && fail()").evaluate(vars(), functions), false);
        assertEquals(Expression.compile("true || fail()").evaluate(vars(), functions), true);
        assertThrows(ExpressionException.class, () -> eval("1 && true"));
    }

    @Test
    public void testSyntaxErrors() {
        String[] invalid = {
            "", "r_sub ==", "(r_sub", "r_sub)", "'unterminated", "r_sub = 'a'", "r_sub in", "1 2",
            // AviatorScript syntax that is not part of Casbin.
            "seq.list('A', 'B')",
            "seq.map(r_items, lambda(x) -> x * 2)",
            "string.startsWith(r_path, '/admin')",
            "math.sqrt(r_value) > 10",
            "lambda(x) -> x * 2",
            "(x) => x * 2",
            "let x = 1",
            "for x in r_items { x * 2 }",
            "while x < 10 { x = x + 1 }",
            "if r_age > 18 then 'adult' else 'minor'",
            "use java.util.*",
            "r_sub.getName()",
        };
        for (String expression : invalid) {
            try {
                Expression.compile(expression);
                fail("expected a syntax error: " + expression);
            } catch (ExpressionException expected) {
            }
        }
    }

    @Test
    public void testEvalRejectsInvalidRules() {
        Map<String, Object> env = vars("r_path", "/admin", "r_value", 200);
        assertFalse(BuiltInFunctions.eval("string.startsWith(r_path, '/admin')", env, null));
        assertFalse(BuiltInFunctions.eval("math.sqrt(r_value) > 10", env, null));
        assertTrue(BuiltInFunctions.eval("keyMatch(r_path, '/admin*') && r_value > 10", env, null));
    }
}
