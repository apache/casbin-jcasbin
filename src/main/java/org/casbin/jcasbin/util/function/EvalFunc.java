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

package org.casbin.jcasbin.util.function;

import org.casbin.jcasbin.expression.EvaluationContext;
import org.casbin.jcasbin.expression.ExpressionException;
import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.Util;

/**
 * EvalFunc is the wrapper for eval.
 * It evaluates a rule stored in the policy, such as "r.sub.Age > 18",
 * with the variables and functions of the current matcher.
 *
 * @author shink
 */
public class EvalFunc implements ExpressionFunction {

    @Override
    public Object call(Object... args) {
        throw new ExpressionException("eval can only be called from a matcher");
    }

    @Override
    public Object call(EvaluationContext context, Object... args) {
        FunctionArgs.checkCount("eval", args, 1);
        String eval = Util.escapeAssertion(FunctionArgs.getString(args, 0));
        return BuiltInFunctions.eval(eval, context.getVariables(), context.getFunctions());
    }

    public String getName() {
        return "eval";
    }
}
