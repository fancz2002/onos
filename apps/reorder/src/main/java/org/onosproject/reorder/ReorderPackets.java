/*
 * Copyright 2017 Open Networking Laboratory
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
package org.onosproject.reorder;

//import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.onosproject.net.flowobjective.Objective.DEFAULT_PRIORITY;
import static org.onosproject.net.flowobjective.Objective.DEFAULT_TIMEOUT;

//import org.apache.felix.scr.annotations.Service;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class ReorderPackets {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Property(name = "flowPriority", intValue = DEFAULT_PRIORITY,
            label = "Configure Flow Priority for installed flow rules; " +
                    "default is 10")
    private int flowPriority = DEFAULT_PRIORITY;


    @Property(name = "flowTimeout", intValue = DEFAULT_TIMEOUT,
            label = "Configure Flow Timeout for installed flow rules; " +
                    "default is 10 sec")
    private int flowTimeout = DEFAULT_TIMEOUT;


    Map baseStations = new HashMap();

    /**
     * The data structure in which the status of controller plan of the
     * base stations are stored.
     */
    public class BaseStationStatus {
        int status;
    }

    private ApplicationId appId;

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Activate
    protected void activate() {
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
    }

    private class handoverStatus {
        DeviceId srcOFId;
        MacAddress srcOFMacAddress;
        IpAddress srcHostIp;
        DeviceId dstOFId;
        MacAddress dstOFMacAddress;
        IpAddress dstHostIp;
        DeviceId gatewayOFId;
        MacAddress gatewayOFMacAddress;
        IpAddress gatewayHostIp;
        HostId ue;
        IpAddress ueIp;

        //        public handoverStatus(DeviceId srcOF, DeviceId dstOF, DeviceId gatewayOF, HostId ue){
        public handoverStatus(Host src, Host dst, Host gateway, Host ue) {
            this.srcOFId = src.location().deviceId();
            this.dstOFId = dst.location().deviceId();
            this.gatewayOFId = gateway.location().deviceId();
            this.srcHostIp = src.ipAddresses().iterator().next();
            this.dstHostIp = dst.ipAddresses().iterator().next();
            this.gatewayHostIp = gateway.ipAddresses().iterator().next();
            this.ueIp = ue.ipAddresses().iterator().next();
        }
    }

    private HashMap<Integer, handoverStatus> handoverStatuses = new HashMap<>();
    private int handoverCount = 0;

    private int getNumberFromPayload(String payload) {
        String[] parsedPayload = payload.split(" ");
        if (parsedPayload.length < 2) {
            log.info(" Parsing payload error! Payload : {}", payload);
            return -1;
        }
        int id = Integer.valueOf(parsedPayload[1]);
        return id;
    }

    private void startHandover(String upperPayload) {
        // Try to parse everything
        IpAddress srcIpAddress, dstIpAddress, gatewayIpAddress, ueIpAddress;
        String[] parsedPayload = upperPayload.split(" ");
        if (parsedPayload.length < 4) {
            log.info("Received an unrecognizable message, {}", parsedPayload);
        }
        int id = Integer.valueOf(upperPayload.split(" ")[1]);
        srcIpAddress = IpAddress.valueOf(upperPayload.split(" ")[2]);
        dstIpAddress = IpAddress.valueOf(upperPayload.split(" ")[3]);
        gatewayIpAddress = IpAddress.valueOf(upperPayload.split(" ")[4]);
        ueIpAddress = IpAddress.valueOf(upperPayload.split(" ")[5]);
        Host src = getHostByIp(srcIpAddress);
        Host dst = getHostByIp(dstIpAddress);
        Host gateway = getHostByIp(gatewayIpAddress);
        Host ue = getHostByIp(ueIpAddress);
        if (src != null && dst != null && gateway != null) {
            handoverStatuses.put(id, new handoverStatus(src, dst, gateway, ue));
        } else {
            log.info("Error in starting handover : src/dst/gateway/ue not found.");
        }
        // Create a entry in handoverStatus
    }


    private void deleteFlowRule(DeviceId target, IpAddress srcIpAddress, IpAddress dstIpAddress) {
        //todo : delete specific flow table rule at target
        log.trace("Searching for flow rules to remove from: " + target);
        log.trace("Removing flows w/ SRC=" + srcIpAddress + ", DST=" + dstIpAddress);
        for (FlowEntry r : flowRuleService.getFlowEntries(target)) {
            boolean matchesSrc = false, matchesDst = false;
            // if the flow has matching src and dst
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.IPV4_DST) {
                    if (((IPCriterion) cr).ip().equals(IpPrefix.valueOf(dstIpAddress, 32))) {
                        matchesDst = true;
                    }
                } else if (cr.type() == Criterion.Type.IPV4_SRC) {
                    if (((IPCriterion) cr).ip().equals(IpPrefix.valueOf(srcIpAddress, 32))) {
                        matchesSrc = true;
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: " + target);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }
    }


    private void redirectPktsToBuffer(int id) {
        TrafficSelector selector;
        TrafficTreatment treatment;
        handoverStatus status = handoverStatuses.get(id);

        //! Pkts from src Host to UE Host goes to Queue 1 (dst OF), this means delete flows matching packets from src OF to UE
        deleteFlowRule(status.dstOFId, status.srcHostIp, status.ueIp);

        //! Pkts from gateway Host to UE Host goes to Queue 2 (dst OF), this means delete flows matching packets from gateway to UE
        deleteFlowRule(status.dstOFId, status.gatewayHostIp, status.ueIp);

        //! Pkts to UE goes to dst OF (src OF)
        Path pathFromsrcOFTodstOF = topologyService.getPaths(topologyService.currentTopology(), status.srcOFId, status.dstOFId).iterator().next();
        selector = DefaultTrafficSelector.builder().
                matchIPDst(IpPrefix.valueOf(status.ueIp, 32)).
                build();
        treatment = DefaultTrafficTreatment.builder().
                setOutput(pathFromsrcOFTodstOF.links().get(0).dst().port())
                .build();
        installForwardRule(status.srcOFId, selector, treatment);

        //! Pkts to UE goes to dst OF (gateway)
        Path pathFromgatewayTodstOF = topologyService.getPaths(topologyService.currentTopology(), status.srcOFId, status.dstOFId).iterator().next();
        selector = DefaultTrafficSelector.builder().
                matchIPDst(IpPrefix.valueOf(status.ueIp, 32)).
                build();
        treatment = DefaultTrafficTreatment.builder()
                .setOutput(pathFromgatewayTodstOF.links().get(0).dst().port())
                .build();
        installForwardRule(status.gatewayOFId, selector, treatment);
    }

    private void sendBufferedPktsToUE(int id) {
        TrafficSelector selector;
        TrafficTreatment treatment;
        handoverStatus status = handoverStatuses.get(id);

        // Pkts from Q1 goes to UE (dst OF)
        selector = DefaultTrafficSelector.builder().build(); //todo : select packets intended to ue
        treatment = DefaultTrafficTreatment.builder().build();
//        addHost2Host(status.dstOF, status.ue, selector, treatment); //todo : select packets intended to

        // Pkts from Q2 goes to UE (dst OF)

    }

    private void cleanUpFlowRules(int id) {
        // Clean all flows to UE (src OF)

    }

    private Host getHostByIp(IpAddress ipAddress) {
        Set<Host> src = hostService.getHostsByIp(ipAddress);
        if (src.size() == 1) {
            for (Host host : src) {
                return host;
            }
        } else {
            log.info("Cannot get host by ip {}. {} found.", ipAddress, src.size());
        }
        return null;
    }

    private class HandoverControllerPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            // If processed, then return
            if (context.isHandled()) {
                return;
            }

            IPacket pkt = context.inPacket().parsed().getPayload();
            if (pkt instanceof IPv4) {
                IPacket payload = pkt.getPayload();
                if (payload instanceof TCP) { // This is a TCP packet and we will deparse its payload.
                    IPacket tcpPayload = payload.getPayload();
                    IPacket controlPayload = tcpPayload.getPayload();
                    byte[] serializedData = controlPayload.serialize();
                    int messageType = -1;
                    String upperPayload = serializedData.toString();
                    if (upperPayload.startsWith("Reorder-0")) {
                        messageType = 0;
                        startHandover(upperPayload);

                    } else if (serializedData == "Reorder-1".getBytes()) {
                        messageType = 1;
                        int handoverId = getNumberFromPayload(upperPayload);
                        if (handoverId != -1) {
                            redirectPktsToBuffer(handoverId);
                        } else {
                            return;
                        }
                    } else if (serializedData == "Reorder-2".getBytes()) {
                        messageType = 2;
                        int handoverId = getNumberFromPayload(upperPayload);
                        if (handoverId != -1) {
                            sendBufferedPktsToUE(handoverId);
                        } else {
                            return;
                        }
                    } else if (serializedData == "Reorder-3".getBytes()) {
                        messageType = 3;
                        int handoverId = getNumberFromPayload(upperPayload);
                        if (handoverId != -1) {
                            cleanUpFlowRules(handoverId);
                        } else {
                            return;
                        }
                    } else if (serializedData == "Reorder-4".getBytes()) {
                        messageType = 4;
                    } else {
                        messageType = -1;
                        log.info("Received an unrecognizable message, {}", serializedData.toString());
                    }
                }
            }


//
//            HostId srdId = HostId.hostId(ethPkt.getSourceMAC());
//            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
//
//            Host dst = hostService.getHost(dstId);
//
//            if (dst.equals(null)){
//                flood (context);
//                return;
//            } else {
//                setUpConnectivity (context, srdId, dstId);
//                forward(context,dst);
//            }
        }
    }

//    private void send(MacAddress srcMacAddress) {
//        Host dst = hostService.getHost(HostId.hostId(srcMacAddress));
//        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
//        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(), treatment);
//        packetService.emit(packet);
//    }

    private void flood(PacketContext cxt) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(), cxt.inPacket().receivedFrom())) {
            packetOut(cxt, PortNumber.FLOOD);
        } else {
            cxt.block();
        }
    }

    private void packetOut(PacketContext cxt, PortNumber portNumber) {
        cxt.treatmentBuilder().setOutput(portNumber);
        cxt.send();
    }

    private void forward(PacketContext cxt, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket pkt = new DefaultOutboundPacket(dst.location().deviceId(), treatment, cxt.inPacket().unparsed());
        packetService.emit(pkt);
        log.info("sending packet : {}", pkt);
    }

    private void installForwardRule(DeviceId target, TrafficSelector selector, TrafficTreatment treatment) {
//        TrafficSelector selector = DefaultTrafficSelector.builder().build();
//        TrafficTreatment treatment = DefaultTrafficTreatment.builder().build();
//        HostToHostIntent i1 = HostToHostIntent.builder()
//                .appId(appId)
//                .one(srdId)
//                .two(dstId)
//                .treatment(treatment)
//                .selector(selector)
//                .build();
//        intentService.submit(i1);
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();
        flowObjectiveService.forward(target, forwardingObjective);
    }


}
