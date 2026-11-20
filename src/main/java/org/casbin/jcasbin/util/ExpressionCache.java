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

package org.casbin.jcasbin.util;

import org.casbin.jcasbin.expression.Expression;

import java.util.function.Function;

/**
 * Bounded cache of compiled {@link Expression} objects, keyed by expression source text.
 * Implementations must be thread-safe.
 */
public interface ExpressionCache {

    /**
     * Returns the cached expression, compiling via {@code loader} on a miss.
     * The loader must be fast and must not call back into this cache (it may run under a lock).
     *
     * @param key    the expression source text.
     * @param loader compiles the expression on a miss.
     * @return the compiled expression.
     */
    Expression get(String key, Function<String, Expression> loader);

    /**
     * Discards all cached expressions. Called when the model's matcher changes;
     * the eval cache does not need it.
     */
    void clear();
}
