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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.cache.Cache;
import org.casbin.jcasbin.persist.cache.CacheableParam;
import org.casbin.jcasbin.persist.cache.DefaultCache;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;

public class SyncedCachedEnforcer extends SyncedEnforcer{
    private Duration expireTime;
    private Cache cache;
    private final AtomicBoolean enableCache = new AtomicBoolean(true);
    private final Object cacheVersionLock = new Object();
    private volatile long cacheVersion = -1;

    /**
     * Default constructor. Initializes a new SyncedCachedEnforcer with a default cache.
     */
    public SyncedCachedEnforcer(){
        super();
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  The path of the model file.
     * @param policyFile The path of the policy file.
     */
    public SyncedCachedEnforcer(String modelPath, String policyFile){
        super(modelPath, policyFile);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a database adapter.
     *
     * @param modelPath The path of the model file.
     * @param adapter   The adapter for the database.
     */
    public SyncedCachedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file, a database adapter, and a logging flag.
     *
     * @param modelPath The path of the model file.
     * @param adapter   The adapter for the database.
     * @param enableLog Whether to enable logging for Casbin.
     */
    public SyncedCachedEnforcer(String modelPath, Adapter adapter, boolean enableLog) {
        super(modelPath, adapter, enableLog);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model and a database adapter.
     *
     * @param m       The model.
     * @param adapter The adapter for the database.
     */
    public SyncedCachedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model, a database adapter, and a logging flag.
     *
     * @param m         The model.
     * @param adapter   The adapter for the database.
     * @param enableLog Whether to enable logging for Casbin.
     */
    public SyncedCachedEnforcer(Model m, Adapter adapter, boolean enableLog) {
        super(m, adapter, enableLog);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model.
     *
     * @param m The model.
     */
    public SyncedCachedEnforcer(Model m) {
        super(m);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file.
     *
     * @param modelPath The path of the model file.
     */
    public SyncedCachedEnforcer(String modelPath) {
        super(modelPath);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file, a policy file, and a logging flag.
     *
     * @param modelPath  The path of the model file.
     * @param policyFile The path of the policy file.
     * @param enableLog  Whether to enable logging for Casbin.
     */
    public SyncedCachedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
        this.cache = new DefaultCache();
    }

    /**
     * Enables or disables caching.
     *
     * @param enable Whether to enable caching.
     */
    public void enableCache(boolean enable) {
        enableCache.set(enable);
    }

    /**
     * Performs an enforcement check based on given parameters, using the cache.
     * Cached decisions are dropped whenever the policy, the role links or the
     * enforcer settings change, so a revoked permission is never served from the cache.
     *
     * @param rvals Parameters for the enforcement check.
     * @return The result of the enforcement check.
     */
    @Override
    public boolean enforce(Object... rvals) {
        if (!enableCache.get() || !isEnforceEnabled()) {
            return super.enforce(rvals);
        }

        String key = getKey(rvals);
        if (key == null) {
            return super.enforce(rvals);
        }

        Lock lock = getReadWriteLock().readLock();
        lock.lock();
        try {
            long version = getPolicyVersion();
            syncCacheVersion(version);

            Boolean cachedResult = cache.get(key);
            if (cachedResult != null) {
                return cachedResult;
            }

            boolean result = super.enforce(rvals);
            if (getPolicyVersion() == version) {
                cache.set(key, result, expireTime);
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    private void syncCacheVersion(long version) {
        if (cacheVersion == version) {
            return;
        }
        synchronized (cacheVersionLock) {
            if (cacheVersion != version) {
                cache.clear();
                cacheVersion = version;
            }
        }
    }

    /**
     * Sets the cache expiration time.
     *
     * @param expireTime The expiration time.
     */
    public void setExpireTime(Duration expireTime) {
        getReadWriteLock().writeLock().lock();
        try {
            this.expireTime = expireTime;
        } finally {
            getReadWriteLock().writeLock().unlock();
        }
    }

    /**
     * Sets a custom cache.
     *
     * @param cache The custom cache.
     */
    public void setCache(Cache cache) {
        getReadWriteLock().writeLock().lock();
        try {
            this.cache = cache;
            bumpPolicyVersion();
        } finally {
            getReadWriteLock().writeLock().unlock();
        }
    }

    /**
     * Retrieves a cache key from the given parameters.
     *
     * @param params The parameters for generating the key.
     * @return The generated cache key as a string.
     */
    public String getCacheKey(Object... params) {
        StringBuilder key = new StringBuilder();
        for (Object param : params) {
            if (param instanceof String) {
                CachedEnforcer.appendCacheKeyPart(key, 's', (String) param);
            } else if (param instanceof CacheableParam) {
                CachedEnforcer.appendCacheKeyPart(key, 'c', ((CacheableParam) param).getCacheKey());
            } else {
                return "";
            }
        }
        return key.toString();
    }

    /**
     * Generates a key based on the given parameters.
     *
     * @param params Parameters.
     * @return The generated key.
     */
    private String getKey(Object... params) {
        String key = getCacheKey(params);
        return key.isEmpty() && params.length > 0 ? null : key;
    }

    /**
     * Invalidates the cache by clearing it.
     */
    public void invalidateCache() {
        getReadWriteLock().writeLock().lock();
        try {
            bumpPolicyVersion();
            cache.clear();
        } finally {
            getReadWriteLock().writeLock().unlock();
        }
    }
}
