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

/**
 * ExpressionFunction is a function that can be called from a matcher, such as keyMatch(r.obj, p.obj).
 */
@FunctionalInterface
public interface ExpressionFunction {
    /**
     * call invokes the function.
     *
     * @param args the evaluated arguments: String, Long, Double, Boolean, null,
     *             List for array literals, or any object passed in the request.
     * @return the result, usually a Boolean or a String.
     */
    Object call(Object... args);

    /**
     * call invokes the function with access to the variables and functions of the
     * current evaluation. Override it when the function needs them, like eval() does.
     *
     * @param context the current evaluation context.
     * @param args    the evaluated arguments.
     * @return the result.
     */
    default Object call(EvaluationContext context, Object... args) {
        return call(args);
    }
}
