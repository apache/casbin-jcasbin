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

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PropertyReader reads attributes such as r.sub.Age from request objects: map entries,
 * JavaBean getters, record accessors and public fields. It never calls other methods.
 */
final class PropertyReader {
    private interface Accessor {
        Object get(Object target) throws ReflectiveOperationException;
    }

    private static final Accessor MISSING = target -> null;
    private static final Map<Class<?>, Map<String, Accessor>> ACCESSORS = new ConcurrentHashMap<>();

    private PropertyReader() {
    }

    static Object get(Object target, String name) {
        if (target == null) {
            return null;
        }
        if (target instanceof Map) {
            return ((Map<?, ?>) target).get(name);
        }

        Class<?> type = target.getClass();
        Accessor accessor = ACCESSORS.computeIfAbsent(type, k -> new ConcurrentHashMap<>())
            .computeIfAbsent(name, k -> find(type, name));
        if (accessor == MISSING) {
            throw new ExpressionException("no property '" + name + "' on " + type.getName());
        }
        try {
            return accessor.get(target);
        } catch (InvocationTargetException e) {
            throw new ExpressionException("failed to read property '" + name + "' on " + type.getName(), e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new ExpressionException("failed to read property '" + name + "' on " + type.getName(), e);
        }
    }

    private static Accessor find(Class<?> type, String name) {
        if (name.isEmpty()) {
            return MISSING;
        }
        String capitalized = Character.toUpperCase(name.charAt(0)) + name.substring(1);
        Method method = getter(type, "get" + capitalized);
        if (method == null) {
            method = getter(type, "is" + capitalized);
            if (method != null && method.getReturnType() != boolean.class && method.getReturnType() != Boolean.class) {
                method = null;
            }
        }
        if (method == null && isRecord(type)) {
            method = getter(type, name);
        }
        if (method != null) {
            if (method.getName().equals("getClass")) {
                return MISSING;
            }
            Method m = method;
            return m::invoke;
        }

        try {
            Field field = type.getField(name);
            if (!Modifier.isStatic(field.getModifiers())) {
                makeAccessible(field);
                return field::get;
            }
        } catch (NoSuchFieldException ignored) {
        }
        return MISSING;
    }

    private static Method getter(Class<?> type, String methodName) {
        try {
            Method method = type.getMethod(methodName);
            if (Modifier.isStatic(method.getModifiers()) || method.getReturnType() == void.class) {
                return null;
            }
            makeAccessible(method);
            return method;
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    private static boolean isRecord(Class<?> type) {
        Class<?> superclass = type.getSuperclass();
        return superclass != null && "java.lang.Record".equals(superclass.getName());
    }

    // Public members of non-public classes, such as a private nested class, still need this.
    private static void makeAccessible(java.lang.reflect.AccessibleObject member) {
        try {
            member.setAccessible(true);
        } catch (RuntimeException ignored) {
        }
    }
}
