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
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Helper;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.casbin.jcasbin.model.Model.requiredSections;
import static org.casbin.jcasbin.model.Model.sectionNameMap;
import static org.testng.Assert.*;

public class ModelTest {

    private String basicExample = "examples/basic_model.conf";

    private static final MockConfig basicConfig = new MockConfig();

    static {
        basicConfig.setData("request_definition::r", "sub, obj, act");
        basicConfig.setData("policy_definition::p", "sub, obj, act");
        basicConfig.setData("policy_effect::e", "some(where (p.eft == allow))");
        basicConfig.setData("matchers::m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act");
    }

    public static class MockConfig extends Config {
        private final Map<String, String> testData = new HashMap<>();

        public MockConfig() {
            super();
        }

        private void setData(String key, String value) {
            testData.put(key, value);
        }

        @Override
        public String getString(String key) {
            if (testData.get(key) == null)
                return "";
            return testData.get(key);
        }
    }

    @Test
    public void testNewModel() {
        Model m = Model.newModel();
        assertNotNull(m);
    }

    @Test
    public void testNewModelFromFile() {
        Model m = Model.newModelFromFile(basicExample);
        assertNotNull(m);
    }

    @Test
    public void testLoadPolicyLineWithoutPolicyType() throws IOException {
        Model m = Model.newModelFromString(new String(Files.readAllBytes(Paths.get(basicExample))));
        Helper.loadPolicyLine("   ", m);
        Helper.loadPolicyLine("p, alice, data1, read", m);
        assertEquals(m.getPolicy("p", "p").size(), 1);
        assertThrows(IllegalArgumentException.class, () -> Helper.loadPolicyLine(" , alice, data1, read", m));
        assertEquals(m.getPolicy("p", "p").size(), 1);
    }

    @Test
    public void testNewModelFromString() throws IOException {
        String modelString = new String(Files.readAllBytes(Paths.get(basicExample)));
        Model m = Model.newModelFromString(modelString);
        assertNotNull(m);
    }

    @Test
    public void testLoadModelFromConfig() {
        Model m = new Model();
        try {
            m.loadModelFromConfig(basicConfig);
        } catch (Exception e) {
            fail("basic config should not return an error");
        }

        m = new Model();
        try {
            m.loadModelFromConfig(new MockConfig());
            fail("empty config should return error");
        } catch (RuntimeException e) {
            // check for missing sections in message
            for (String rs : requiredSections) {
                assertTrue(e.getMessage().contains(sectionNameMap.get(rs)),
                    "section name: " + sectionNameMap.get(rs) + " should be in message");
            }
        }
    }

    @Test
    public void testHasSection() {
        Model m = new Model();
        m.loadModelFromConfig(basicConfig);
        for (String sec : requiredSections) {
            assertTrue(m.hasSection(sec), sec + " section was expected in model");
        }

        m = new Model();
        try {
            m.loadModelFromConfig(new MockConfig());
        }catch (RuntimeException e){
        }finally {
            for (String sec : requiredSections) {
                assertFalse(m.hasSection(sec), sec + " section was not expected in model");
            }
        }
    }

    @Test
    public void testModelAddDef() {
        Model m = new Model();
        assertEquals(true, m.addDef("r", "r", "sub, obj, act"));
        assertEquals(false, m.addDef("r", "r", ""));
    }

    @Test
    public void testModelToText() {
        testModelToText("r.sub == p.sub && r.obj == p.obj && r_func(r.act, p.act) && testr_func(r.act, p.act)", "r_sub == p_sub && r_obj == p_obj && r_func(r_act, p_act) && testr_func(r_act, p_act)");
        testModelToText("r.sub == p.sub && r.obj == p.obj && p_func(r.act, p.act) && testp_func(r.act, p.act)", "r_sub == p_sub && r_obj == p_obj && p_func(r_act, p_act) && testp_func(r_act, p_act)");
    }

    private void testModelToText(String mData, String mExpected) {
        Model m = new Model();

        String[] ptypes = {"r", "p", "e", "m"};
        String[] values = {"sub, obj, act", "sub, obj, act", "some(where (p.eft == allow))", mData};
        String[] expectedValues = {"sub, obj, act", "sub, obj, act", "some(where (p_eft == allow))", mExpected};

        for (int i = 0; i < ptypes.length; i++) {
            m.addDef(ptypes[i], ptypes[i], values[i]);
        }

        Model newM = new Model();
        System.out.println(m.toText());
        newM.loadModelFromText(m.toText());

        for (int i = 0; i < ptypes.length; i++) {
            assertEquals(expectedValues[i], newM.model.get(ptypes[i]).get(ptypes[i]).value);
        }
    }
}
