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

import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.util.BuiltInFunctions;

/**
 * KeyMatch2Func is the wrapper for keyMatch2.
 */
public class KeyMatch2Func implements ExpressionFunction {
    @Override
    public Object call(Object... args) {
        FunctionArgs.checkCount("keyMatch2", args, 2);
        String key1 = FunctionArgs.getString(args, 0);
        String key2 = FunctionArgs.getString(args, 1);

        return BuiltInFunctions.keyMatch2(key1, key2);
    }

    public String getName() {
        return "keyMatch2";
    }
}
