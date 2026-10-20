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

import com.google.gson.Gson;
import org.testng.SkipException;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertTrue;

public class ConformanceTest {
    static class ConformanceCase {
        String model;
        String policy;
        List<ConformanceRequest> tests;
    }

    static class ConformanceRequest {
        List<String> request;
        boolean allow;
        List<String> explain;
    }

    @Test
    public void testConformance() throws IOException {
        String dir = System.getenv("CASBIN_CONFORMANCE_DIR");
        if (dir == null || dir.isEmpty()) {
            throw new SkipException("CASBIN_CONFORMANCE_DIR is not set");
        }

        File[] files = new File(dir, "cases").listFiles((d, name) -> name.endsWith(".json"));
        assertTrue(files != null && files.length > 0, "no conformance cases found in " + dir);
        Arrays.sort(files);

        List<String> failures = new ArrayList<>();
        for (File file : files) {
            ConformanceCase c = new Gson().fromJson(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8), ConformanceCase.class);
            Enforcer e;
            try {
                e = new Enforcer(new File(dir, "data/" + c.model).getPath(), new File(dir, "data/" + c.policy).getPath());
            } catch (Exception ex) {
                failures.add(file.getName() + ": " + ex);
                continue;
            }
            for (ConformanceRequest test : c.tests) {
                try {
                    EnforceResult result = e.enforceEx(test.request.toArray());
                    List<String> explain = result.getExplain() == null ? Collections.emptyList() : result.getExplain();
                    if (result.isAllow() != test.allow || !explain.equals(test.explain)) {
                        failures.add(file.getName() + " " + test.request + ": got (" + result.isAllow() + ", " + explain + "), want (" + test.allow + ", " + test.explain + ")");
                    }
                } catch (Exception ex) {
                    failures.add(file.getName() + " " + test.request + ": " + ex);
                }
            }
        }
        assertTrue(failures.isEmpty(), failures.size() + " conformance failures:\n" + String.join("\n", failures));
    }
}
