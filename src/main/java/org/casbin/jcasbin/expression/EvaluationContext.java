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

import java.util.Collections;
import java.util.Map;

/**
 * EvaluationContext holds the variables (such as r_sub, p_obj) and the functions
 * an expression is evaluated with.
 */
public class EvaluationContext {
    private final Map<String, Object> variables;
    private final Map<String, ? extends ExpressionFunction> functions;

    public EvaluationContext(Map<String, Object> variables, Map<String, ? extends ExpressionFunction> functions) {
        this.variables = variables == null ? Collections.emptyMap() : variables;
        this.functions = functions == null ? Collections.emptyMap() : functions;
    }

    public Map<String, Object> getVariables() {
        return variables;
    }

    public Map<String, ? extends ExpressionFunction> getFunctions() {
        return functions;
    }
}
