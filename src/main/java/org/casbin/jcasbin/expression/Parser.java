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

import org.casbin.jcasbin.expression.Lexer.Kind;
import org.casbin.jcasbin.expression.Lexer.Token;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Parser builds the syntax tree of a matcher. Operator precedence follows the Go
 * implementation (govaluate), from lowest to highest:
 * ?: and ??, ||, &amp;&amp;, comparisons (== != &lt; &gt; &lt;= &gt;= =~ !~ in), |, ^, &amp;,
 * &lt;&lt; &gt;&gt;, + -, * / %, **, unary - ! ~. Binary operators are left-associative.
 */
class Parser {
    interface Node {
        Object eval(EvaluationContext context);
    }

    private static final Set<String> COMPARATORS = new HashSet<>(Arrays.asList("==", "!=", "<", ">", "<=", ">=", "=~", "!~"));

    private final String source;
    private final List<Token> tokens;
    private int index;

    private Parser(String source) {
        this.source = source;
        this.tokens = Lexer.tokenize(source);
    }

    static Node parse(String source) {
        Parser parser = new Parser(source);
        Node node = parser.ternary();
        if (parser.peek().kind != Kind.EOF) {
            throw parser.error("unexpected " + parser.peek());
        }
        return node;
    }

    private Token peek() {
        return tokens.get(index);
    }

    private Token advance() {
        return tokens.get(index++);
    }

    private boolean accept(String operator) {
        if (peek().is(operator)) {
            index++;
            return true;
        }
        return false;
    }

    private void expect(String operator) {
        if (!accept(operator)) {
            throw error("expected '" + operator + "' but found " + peek());
        }
    }

    private ExpressionException error(String message) {
        return new ExpressionException(message + " at position " + peek().position + " in: " + source);
    }

    private Node ternary() {
        Node condition = or();
        if (accept("?")) {
            Node whenTrue = ternary();
            expect(":");
            Node whenFalse = ternary();
            return ctx -> Operations.toBoolean(condition.eval(ctx), "?") ? whenTrue.eval(ctx) : whenFalse.eval(ctx);
        }
        if (accept("??")) {
            Node fallback = ternary();
            return ctx -> {
                Object value = condition.eval(ctx);
                return value != null ? value : fallback.eval(ctx);
            };
        }
        return condition;
    }

    private Node or() {
        Node left = and();
        while (accept("||")) {
            Node l = left;
            Node r = and();
            left = ctx -> Operations.toBoolean(l.eval(ctx), "||") || Operations.toBoolean(r.eval(ctx), "||");
        }
        return left;
    }

    private Node and() {
        Node left = comparison();
        while (accept("&&")) {
            Node l = left;
            Node r = comparison();
            left = ctx -> Operations.toBoolean(l.eval(ctx), "&&") && Operations.toBoolean(r.eval(ctx), "&&");
        }
        return left;
    }

    private Node comparison() {
        Node left = binary(0);
        while (true) {
            Token token = peek();
            String op;
            if (token.kind == Kind.OPERATOR && COMPARATORS.contains(token.text)) {
                op = token.text;
            } else if (token.kind == Kind.IDENTIFIER && token.text.equals("in")) {
                op = "in";
            } else {
                return left;
            }
            index++;
            Node l = left;
            Node r = op.equals("in") && peek().is("(") ? inList() : binary(0);
            left = comparator(op, l, r);
        }
    }

    // After 'in', a parenthesized single value such as ('admin') is a one-element list, as in Go.
    private Node inList() {
        expect("(");
        List<Node> items = list(")");
        if (items.size() != 1 || tokens.get(index - 2).is(",")) {
            return array(items);
        }
        Node item = items.get(0);
        return ctx -> {
            Object value = item.eval(ctx);
            if (value instanceof Collection || (value != null && value.getClass().isArray())) {
                return value;
            }
            return Collections.singletonList(value);
        };
    }

    private static Node comparator(String op, Node l, Node r) {
        switch (op) {
            case "==": return ctx -> Operations.equal(l.eval(ctx), r.eval(ctx));
            case "!=": return ctx -> !Operations.equal(l.eval(ctx), r.eval(ctx));
            case "<": return ctx -> Operations.compare(l.eval(ctx), r.eval(ctx), op) < 0;
            case ">": return ctx -> Operations.compare(l.eval(ctx), r.eval(ctx), op) > 0;
            case "<=": return ctx -> Operations.compare(l.eval(ctx), r.eval(ctx), op) <= 0;
            case ">=": return ctx -> Operations.compare(l.eval(ctx), r.eval(ctx), op) >= 0;
            case "=~": return ctx -> Operations.regexMatch(l.eval(ctx), r.eval(ctx));
            case "!~": return ctx -> !Operations.regexMatch(l.eval(ctx), r.eval(ctx));
            default: return ctx -> Operations.in(l.eval(ctx), r.eval(ctx));
        }
    }

    // Left-associative binary levels between comparisons and unary operators, lowest first.
    private static final String[][] BINARY_LEVELS = {
        {"|"}, {"^"}, {"&"}, {"<<", ">>"}, {"+", "-"}, {"*", "/", "%"}
    };

    private Node binary(int level) {
        if (level == BINARY_LEVELS.length) {
            return power();
        }
        Node left = binary(level + 1);
        while (true) {
            String op = null;
            for (String candidate : BINARY_LEVELS[level]) {
                if (peek().is(candidate)) {
                    op = candidate;
                    break;
                }
            }
            if (op == null) {
                return left;
            }
            index++;
            Node l = left;
            Node r = binary(level + 1);
            String operator = op;
            left = ctx -> Operations.arithmetic(operator, l.eval(ctx), r.eval(ctx));
        }
    }

    private Node power() {
        Node left = unary();
        while (accept("**")) {
            Node l = left;
            Node r = unary();
            left = ctx -> Operations.arithmetic("**", l.eval(ctx), r.eval(ctx));
        }
        return left;
    }

    private Node unary() {
        if (accept("!")) {
            Node operand = unary();
            return ctx -> !Operations.toBoolean(operand.eval(ctx), "!");
        }
        if (accept("-")) {
            Node operand = unary();
            return ctx -> Operations.negate(operand.eval(ctx));
        }
        if (accept("~")) {
            Node operand = unary();
            return ctx -> Operations.bitwiseNot(operand.eval(ctx));
        }
        return primary();
    }

    private Node primary() {
        Token token = advance();
        switch (token.kind) {
            case NUMBER:
            case STRING:
                Object value = token.value;
                return ctx -> value;
            case IDENTIFIER:
                return identifier(token);
            case OPERATOR:
                if (token.text.equals("(")) {
                    List<Node> items = list(")");
                    if (items.size() == 1 && !tokens.get(index - 2).is(",")) {
                        return items.get(0);
                    }
                    return array(items);
                }
                if (token.text.equals("[")) {
                    return array(list("]"));
                }
                break;
            default:
                break;
        }
        index--;
        throw error("unexpected " + token);
    }

    private Node identifier(Token token) {
        String name = token.text;
        switch (name) {
            case "true":
                return ctx -> Boolean.TRUE;
            case "false":
                return ctx -> Boolean.FALSE;
            case "nil":
            case "null":
                return ctx -> null;
            case "in":
                index--;
                throw error("unexpected 'in'");
            default:
                break;
        }

        if (accept("(")) {
            if (name.indexOf('.') >= 0) {
                index--;
                throw error("unknown function '" + name + "'");
            }
            List<Node> args = list(")");
            Node[] argNodes = args.toArray(new Node[0]);
            return ctx -> {
                ExpressionFunction function = ctx.getFunctions().get(name);
                if (function == null) {
                    throw new ExpressionException("unknown function '" + name + "' in: " + source);
                }
                Object[] values = new Object[argNodes.length];
                for (int i = 0; i < argNodes.length; i++) {
                    values[i] = argNodes[i].eval(ctx);
                }
                return function.call(ctx, values);
            };
        }

        String[] path = name.split("\\.");
        if (path.length == 1) {
            return ctx -> ctx.getVariables().get(name);
        }
        return ctx -> {
            Object value = ctx.getVariables().get(path[0]);
            for (int i = 1; i < path.length; i++) {
                value = PropertyReader.get(value, path[i]);
            }
            return value;
        };
    }

    // Parses comma-separated items up to the closing bracket, which is consumed.
    private List<Node> list(String close) {
        List<Node> items = new ArrayList<>();
        if (accept(close)) {
            return items;
        }
        do {
            if (peek().is(close)) {
                break;
            }
            items.add(ternary());
        } while (accept(","));
        expect(close);
        return items;
    }

    private static Node array(List<Node> items) {
        Node[] nodes = items.toArray(new Node[0]);
        return ctx -> {
            List<Object> values = new ArrayList<>(nodes.length);
            for (Node node : nodes) {
                values.add(node.eval(ctx));
            }
            return Collections.unmodifiableList(values);
        };
    }
}
