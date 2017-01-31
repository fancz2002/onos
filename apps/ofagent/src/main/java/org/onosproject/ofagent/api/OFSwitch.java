/*
 * Copyright 2017-present Open Networking Laboratory
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
package org.onosproject.ofagent.api;

import org.onosproject.net.Device;

/**
 * Representation of virtual OpenFlow switch.
 */
public interface OFSwitch extends OFSwitchService, OFControllerRoleService {

    /**
     * Returns the device information.
     *
     * @return virtual device
     */
    Device device();

    /**
     * Returns the capabilities of the switch.
     *
     * @return capabilities
     */
    OFSwitchCapabilities capabilities();

    /**
     * Returns if the switch is connected to controllers or not.
     *
     * @return true if the switch is connected, false otherwise
     */
    boolean isConnected();

    // TODO add builder interface
}