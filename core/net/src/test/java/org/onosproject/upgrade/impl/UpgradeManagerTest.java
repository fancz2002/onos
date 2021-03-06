/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.upgrade.impl;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.junit.Test;
import org.onlab.packet.IpAddress;
import org.onosproject.cluster.UnifiedClusterServiceAdapter;
import org.onosproject.cluster.ControllerNode;
import org.onosproject.cluster.DefaultControllerNode;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.Version;
import org.onosproject.core.VersionServiceAdapter;
import org.onosproject.store.service.AsyncAtomicValue;
import org.onosproject.store.service.AsyncAtomicValueAdapter;
import org.onosproject.store.service.AtomicValue;
import org.onosproject.store.service.AtomicValueAdapter;
import org.onosproject.store.service.AtomicValueBuilder;
import org.onosproject.store.service.CoordinationServiceAdapter;
import org.onosproject.upgrade.Upgrade;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Upgrade manager test.
 */
public class UpgradeManagerTest {

    /**
     * Creates a new upgrade manager to test.
     *
     * @param version the local node version
     * @param state the initial upgrade state
     * @param versions a list of controller node versions
     * @return the activated upgrade manager
     */
    @SuppressWarnings("unchecked")
    private UpgradeManager createUpgradeManager(Version version, Upgrade state, List<Version> versions) {
        UpgradeManager upgradeManager = new UpgradeManager();
        upgradeManager.clusterService = new UnifiedClusterServiceAdapter() {
            @Override
            public Set<ControllerNode> getNodes() {
                AtomicInteger nodeCounter = new AtomicInteger();
                return versions.stream()
                        .map(v -> {
                            int nodeId = nodeCounter.getAndIncrement();
                            return new DefaultControllerNode(
                                    NodeId.nodeId(String.valueOf(nodeId)),
                                    IpAddress.valueOf("127.0.0.1"),
                                    nodeId);
                        })
                        .collect(Collectors.toSet());
            }

            @Override
            public ControllerNode.State getState(NodeId nodeId) {
                return ControllerNode.State.READY;
            }

            @Override
            public Version getVersion(NodeId nodeId) {
                return versions.get(Integer.parseInt(nodeId.id()));
            }
        };

        upgradeManager.versionService = new VersionServiceAdapter() {
            @Override
            public Version version() {
                return version;
            }
        };

        upgradeManager.coordinationService = new CoordinationServiceAdapter() {
            @Override
            public <V> AtomicValueBuilder<V> atomicValueBuilder() {
                return new AtomicValueBuilder<V>() {
                    @Override
                    public AsyncAtomicValue<V> build() {
                        return new AsyncAtomicValueAdapter() {
                            @Override
                            public AtomicValue asAtomicValue() {
                                return new AtomicValueAdapter() {
                                    private Object value = state;

                                    @Override
                                    public void set(Object value) {
                                        this.value = value;
                                    }

                                    @Override
                                    public Object get() {
                                        return value;
                                    }

                                    @Override
                                    public boolean compareAndSet(Object expect, Object update) {
                                        if ((value == null && expect == null)
                                                || (value != null && value.equals(expect))) {
                                            value = update;
                                            return true;
                                        }
                                        return false;
                                    }
                                };
                            }
                        };
                    }
                };
            }
        };

        upgradeManager.activate();
        return upgradeManager;
    }

    @Test
    public void testFailedCommit() throws Exception {
        UpgradeManager upgradeManager = createUpgradeManager(
                Version.version("1.0.0"),
                new Upgrade(Version.version("1.0.0"), Version.version("1.0.0"), Upgrade.Status.INACTIVE),
                Arrays.asList(Version.version("1.0.0"), Version.version("1.0.0"), Version.version("1.0.1")));

        assertEquals(Upgrade.Status.INACTIVE, upgradeManager.getState().status());
        assertTrue(upgradeManager.isLocalActive());
        assertFalse(upgradeManager.isLocalUpgraded());

        upgradeManager.initialize();

        assertEquals(Upgrade.Status.INITIALIZED, upgradeManager.getState().status());
        assertEquals(Version.version("1.0.0"), upgradeManager.getState().source());
        assertEquals(Version.version("1.0.0"), upgradeManager.getState().target());
        assertEquals(Version.version("1.0.0"), upgradeManager.getVersion());
        assertTrue(upgradeManager.isLocalActive());
        assertFalse(upgradeManager.isLocalUpgraded());

        upgradeManager.upgrade();
        assertEquals(Upgrade.Status.UPGRADED, upgradeManager.getState().status());

        try {
            upgradeManager.commit();
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testSuccessfulCommit() throws Exception {
        UpgradeManager upgradeManager = createUpgradeManager(
                Version.version("1.0.1"),
                new Upgrade(Version.version("1.0.0"), Version.version("1.0.1"), Upgrade.Status.UPGRADED),
                Arrays.asList(Version.version("1.0.1"), Version.version("1.0.1"), Version.version("1.0.1")));

        assertEquals(Upgrade.Status.UPGRADED, upgradeManager.getState().status());
        assertTrue(upgradeManager.isLocalActive());
        assertTrue(upgradeManager.isLocalUpgraded());

        upgradeManager.commit();
        assertEquals(Upgrade.Status.INACTIVE, upgradeManager.getState().status());
    }

    @Test
    public void testFailedReset() throws Exception {
        UpgradeManager upgradeManager = createUpgradeManager(
                Version.version("1.0.0"),
                new Upgrade(Version.version("1.0.0"), Version.version("1.0.1"), Upgrade.Status.INITIALIZED),
                Arrays.asList(Version.version("1.0.0"), Version.version("1.0.0"), Version.version("1.0.1")));

        assertEquals(Upgrade.Status.INITIALIZED, upgradeManager.getState().status());
        assertEquals(Version.version("1.0.0"), upgradeManager.getState().source());
        assertEquals(Version.version("1.0.1"), upgradeManager.getState().target());
        assertEquals(Version.version("1.0.0"), upgradeManager.getVersion());
        assertTrue(upgradeManager.isLocalActive());
        assertFalse(upgradeManager.isLocalUpgraded());

        upgradeManager.upgrade();
        assertEquals(Upgrade.Status.UPGRADED, upgradeManager.getState().status());
        assertEquals(Version.version("1.0.1"), upgradeManager.getVersion());

        upgradeManager.rollback();
        assertEquals(Upgrade.Status.ROLLED_BACK, upgradeManager.getState().status());

        try {
            upgradeManager.reset();
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testSuccessfulResetFromInitialized() throws Exception {
        UpgradeManager upgradeManager = createUpgradeManager(
                Version.version("1.0.0"),
                new Upgrade(Version.version("1.0.0"), Version.version("1.0.0"), Upgrade.Status.INITIALIZED),
                Arrays.asList(Version.version("1.0.0"), Version.version("1.0.0"), Version.version("1.0.0")));

        assertEquals(Upgrade.Status.INITIALIZED, upgradeManager.getState().status());
        assertTrue(upgradeManager.isLocalActive());
        assertFalse(upgradeManager.isLocalUpgraded());

        upgradeManager.reset();
        assertEquals(Upgrade.Status.INACTIVE, upgradeManager.getState().status());
    }

    @Test
    public void testSuccessfulResetFromRolledBack() throws Exception {
        UpgradeManager upgradeManager = createUpgradeManager(
                Version.version("1.0.0"),
                new Upgrade(Version.version("1.0.0"), Version.version("1.0.1"), Upgrade.Status.ROLLED_BACK),
                Arrays.asList(Version.version("1.0.0"), Version.version("1.0.0"), Version.version("1.0.0")));

        assertEquals(Upgrade.Status.ROLLED_BACK, upgradeManager.getState().status());
        assertTrue(upgradeManager.isLocalActive());
        assertFalse(upgradeManager.isLocalUpgraded());

        upgradeManager.reset();
        assertEquals(Upgrade.Status.INACTIVE, upgradeManager.getState().status());
    }

}
