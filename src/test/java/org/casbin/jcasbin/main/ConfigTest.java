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

import org.casbin.jcasbin.config.Config;

import org.testng.annotations.Test;
import static org.testng.Assert.*;

public class ConfigTest {

    @Test
    public void testGet() {
        Config config = Config.newConfig("examples/config/testini.ini");

        // default::key test
        assertTrue(config.getBool("debug"));
        assertEquals("act.wiki", config.getString("url"));

        // redis::key test
        String[] redisKeys = config.getStrings("redis::redis.key");
        assertEquals(new String[]{"push1", "push2"}, redisKeys);
        assertEquals("127.0.0.1", config.getString("mysql::mysql.dev.host"));
        assertEquals("10.0.0.1", config.getString("mysql::mysql.master.host"));
        assertEquals("root", config.getString("mysql::mysql.master.user"));
        assertEquals("89dds)2$", config.getString("mysql::mysql.master.pass"));
        assertEquals("\"a#b;c\" 'd#e'", config.getString("mysql::mysql.master.note"));

        // math::key test
        assertEquals(64, config.getInt("math::math.i64"));
        assertEquals(64.1, config.getFloat("math::math.f64"), 0.0001);

        config.set("other::key1", "new test key");
        assertEquals("new test key", config.getString("other::key1"));

        config.set("other::key1", "test key");

        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi1::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi2::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi3::name"));
        assertEquals("", config.getString("multi4::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi5::name"));
    }
}
