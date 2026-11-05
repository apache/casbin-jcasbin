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

import java.util.Map;

/**
 * Expression is a compiled matcher expression, such as
 * {@code g(r_sub, p_sub) && keyMatch(r_obj, p_obj) && r_act == p_act}.
 * It is immutable and can be evaluated concurrently with different variables.
 *
 * <p>The language is the one shared by all Casbin implementations: string, number,
 * boolean and null literals, arrays like {@code ('a', 'b')} or {@code ['a', 'b']},
 * variables with attribute access like {@code r_sub.Age}, function calls, and the
 * operators {@code ?: ?? || && == != < > <= >= =~ !~ in | ^ & << >> + - * / % ! ~ **}.
 * Attribute access reads map entries, getters, record accessors and public fields only.
 */
public final class Expression {
    private final String source;
    private final Parser.Node root;

    private Expression(String source, Parser.Node root) {
        this.source = source;
        this.root = root;
    }

    /**
     * compile parses an expression.
     *
     * @param source the expression text.
     * @return the compiled expression.
     * @throws ExpressionException if the expression is not valid.
     */
    public static Expression compile(String source) {
        if (source == null) {
            throw new ExpressionException("expression is null");
        }
        return new Expression(source, Parser.parse(source));
    }

    /**
     * evaluate evaluates the expression.
     *
     * @param variables the variables, such as r_sub and p_obj.
     * @param functions the functions the expression can call.
     * @return the result.
     * @throws ExpressionException if the evaluation fails.
     */
    public Object evaluate(Map<String, Object> variables, Map<String, ? extends ExpressionFunction> functions) {
        return evaluate(new EvaluationContext(variables, functions));
    }

    /**
     * evaluate evaluates the expression.
     *
     * @param context the variables and functions.
     * @return the result.
     * @throws ExpressionException if the evaluation fails.
     */
    public Object evaluate(EvaluationContext context) {
        return root.eval(context);
    }

    public String getSource() {
        return source;
    }

    @Override
    public String toString() {
        return source;
    }
}
