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

import org.casbin.jcasbin.detector.DefaultDetector;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DetectorTest {
    @Test
    public void acceptsAcyclicGraphAndDuplicateLinks() {
        DefaultRoleManager rm = checkedManager();
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("D", "B");
        rm.addLink("A", "C");
        rm.addLink("A", "B");
        assertTrue(rm.hasLink("D", "C"));
        assertEquals(rm.getUsers("B").size(), 2);
        assertNull(new DefaultDetector().check(rm));
    }

    @Test
    public void rejectsCycleAndRollsBackBothDirections() {
        DefaultRoleManager rm = checkedManager();
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        IllegalArgumentException error = expectThrows(IllegalArgumentException.class,
                () -> rm.addLink("C", "A"));
        assertTrue(error.getMessage().startsWith("Cycle detected:"));
        assertTrue(rm.getRoles("C").isEmpty());
        assertTrue(rm.getUsers("A").isEmpty());
        assertFalse(rm.hasLink("C", "A"));
        assertTrue(rm.hasLink("A", "C"));
        assertNull(new DefaultDetector().check(rm));
        rm.addLink("C", "D");
        assertTrue(rm.hasLink("A", "D"));
    }

    @Test
    public void rejectsSelfLoop() {
        DefaultRoleManager rm = checkedManager();
        expectThrows(IllegalArgumentException.class, () -> rm.addLink("A", "A"));
        assertTrue(rm.getRoles("A").isEmpty());
        assertTrue(rm.getUsers("A").isEmpty());
        assertNull(new DefaultDetector().check(rm));
    }

    @Test
    public void detectionIsOptionalAndCanBeDisabled() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.addLink("B", "A");
        assertNotNull(new DefaultDetector().check(rm));
        rm.clear();
        rm.setDetector(new DefaultDetector());
        rm.setDetector(null);
        rm.addLink("A", "A");
        assertNotNull(new DefaultDetector().check(rm));
    }

    @Test
    public void preservesExistingLinkWhenDetectorRejectsDuplicate() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.setDetector(manager -> "rejected");
        IllegalArgumentException error = expectThrows(IllegalArgumentException.class,
                () -> rm.addLink("A", "B"));
        assertEquals(error.getMessage(), "rejected");
        assertTrue(rm.getRoles("A").contains("B"));
        assertTrue(rm.getUsers("B").contains("A"));
    }

    @Test
    public void rollsBackWhenDetectorThrows() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        IllegalStateException failure = new IllegalStateException("checker failed");
        rm.setDetector(manager -> { throw failure; });
        assertSame(expectThrows(IllegalStateException.class, () -> rm.addLink("A", "B")), failure);
        assertTrue(rm.getRoles("A").isEmpty());
        assertTrue(rm.getUsers("B").isEmpty());
    }

    @Test
    public void acceptsEmptyDetectorResult() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.setDetector(manager -> "");
        rm.addLink("A", "B");
        assertTrue(rm.hasLink("A", "B"));
    }

    @Test
    public void clearKeepsDetectorEnabled() {
        DefaultRoleManager rm = checkedManager();
        rm.addLink("A", "B");
        rm.clear();
        expectThrows(IllegalArgumentException.class, () -> rm.addLink("A", "A"));
        assertTrue(rm.getRoles("A").isEmpty());
    }

    private DefaultRoleManager checkedManager() {
        DefaultRoleManager rm = new DefaultRoleManager(10);
        rm.setDetector(new DefaultDetector());
        return rm;
    }
}
