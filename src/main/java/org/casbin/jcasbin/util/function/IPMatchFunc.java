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
 * IPMatchFunc is the wrapper for ipMatch.
 */
public class IPMatchFunc implements ExpressionFunction {
    @Override
    public Object call(Object... args) {
        FunctionArgs.checkCount("ipMatch", args, 2);
        String ip1 = FunctionArgs.getString(args, 0);
        String ip2 = FunctionArgs.getString(args, 1);

        return BuiltInFunctions.ipMatch(ip1, ip2);
    }

    public String getName() {
        return "ipMatch";
    }
}
