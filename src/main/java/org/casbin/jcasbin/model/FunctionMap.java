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

package org.casbin.jcasbin.model;

import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.util.function.*;

import java.util.HashMap;
import java.util.Map;

/**
 * FunctionMap represents the collection of Function.
 */
public class FunctionMap {
    /**
     * fm maps the function names to the functions that can be used in the matchers.
     */
    public Map<String, ExpressionFunction> fm;

    public boolean isModify = false;

    /**
     * addFunction adds an expression function.
     *
     * @param name the name of the new function.
     * @param function the function.
     */
    public void addFunction(String name, ExpressionFunction function) {
        fm.put(name, function);
        isModify=true;
    }

    /**
     * loadFunctionMap loads an initial function map.
     *
     * @return the constructor of FunctionMap.
     */
    public static FunctionMap loadFunctionMap() {
        FunctionMap fm = new FunctionMap();
        fm.fm = new HashMap<>();

        fm.addFunction("keyMatch", new KeyMatchFunc());
        fm.addFunction("keyMatch2", new KeyMatch2Func());
        fm.addFunction("keyMatch3", new KeyMatch3Func());
        fm.addFunction("keyMatch4", new KeyMatch4Func());
        fm.addFunction("keyMatch5", new KeyMatch5Func());
        fm.addFunction("keyGet", new KeyGetFunc());
        fm.addFunction("keyGet2", new KeyGet2Func());
        fm.addFunction("keyGet3", new KeyGet3Func());
        fm.addFunction("regexMatch", new RegexMatchFunc());
        fm.addFunction("ipMatch", new IPMatchFunc());
        fm.addFunction("eval", new EvalFunc());
        fm.addFunction("globMatch", new GlobMatchFunc());

        return fm;
    }
}
