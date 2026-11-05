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

import org.casbin.jcasbin.expression.ExpressionException;

/**
 * FunctionArgs checks the arguments passed to matcher functions.
 */
public final class FunctionArgs {
    private FunctionArgs() {
    }

    /**
     * checkCount checks the number of arguments.
     *
     * @param name     the function name, used in the error message.
     * @param args     the arguments.
     * @param expected the expected number of arguments.
     */
    public static void checkCount(String name, Object[] args, int expected) {
        if (args.length != expected) {
            throw new ExpressionException("wrong number of arguments (" + args.length + ") passed to " + name + ", expected " + expected);
        }
    }

    /**
     * getString returns the argument at index as a string.
     *
     * @param args  the arguments.
     * @param index the index of the argument.
     * @return the string value.
     */
    public static String getString(Object[] args, int index) {
        Object value = args[index];
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Character) {
            return value.toString();
        }
        throw new ExpressionException("argument " + (index + 1) + " must be a string, got "
            + (value == null ? "null" : value + " (" + value.getClass().getSimpleName() + ")"));
    }
}
