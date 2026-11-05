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

import org.casbin.jcasbin.util.function.CustomFunction;
import org.casbin.jcasbin.util.function.FunctionArgs;
import org.testng.annotations.Test;

import java.util.regex.Pattern;

import static org.casbin.jcasbin.main.TestUtil.testEnforce;

public class FunctionTest {

    @Test
    public void testCustomFunction() {
        Enforcer e = new Enforcer("examples/abac_rule_custom_function_model.conf", "examples/abac_rule_custom_function_policy.csv");

        // add a custom function
        CustomFunc customFunc = new CustomFunc();
        e.addFunction(customFunc.getName(), customFunc);

        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("alice", 18), "/test/url1/url2/2", "GET", true);
        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("alice", 18), "/test/2", "GET", false);
        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("bob", 10), "/test/url1/url2/2", "GET", false);
    }

    public static class CustomFunc extends CustomFunction {
        @Override
        public Object call(Object... args) {
            String obj = FunctionArgs.getString(args, 0);
            return Pattern.compile("/*/url1/url2/*", Pattern.CASE_INSENSITIVE).matcher(obj).find();
        }

        @Override
        public String getName() {
            return "custom";
        }
    }
}
