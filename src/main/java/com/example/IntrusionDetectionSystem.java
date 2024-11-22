package com.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class IntrusionDetectionSystem {
    private static final int SNAPSHOT_LENGTH = 65536; // Max bytes per packet
    private static final int READ_TIMEOUT = 50;     // In milliseconds
    private static final int TRAFFIC_THRESHOLD = 100; // Packet count threshold
    private static final int THREAD_POOL_SIZE = 10;
    private static final int SYN_FLOOD_THRESHOLD = 5;

    private static final Map<String, Integer> trafficCount = new ConcurrentHashMap<>();
    private static final Map<String, Set<Integer>> portScanTracker = new ConcurrentHashMap<>();
    private static final Map<String, ConnectionState> connectionTracker = new ConcurrentHashMap<>();
    private static final Map<String, Integer> incompleteConnections = new ConcurrentHashMap<>();
    private static final ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

    public static void main( String[] args ) {
        try {
            System.out.println("da2a2");
            PcapNetworkInterface nif = Pcaps.getDevByName("eth0");
            if (nif == null) {
                System.out.println("No network interface found");
                return;
            }
            System.out.println("Listening on interface " + nif.getName());

            PcapHandle handle = nif.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

            handle.loop(-1, (PacketListener) packet -> executor.submit(() -> processPacket(packet)));

            // Close the handle
            handle.close();
            executor.shutdown();
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static void processPacket(Packet packet) {
        if (packet instanceof UnknownPacket) {
            System.out.println("Unknown packet: " + packet);
        }

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            // Extract source and destination IP addresses
            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            System.out.println("IPv4 Packet: " + srcIp + " -> " + dstIp);

            // Count traffic from each source IP
            trafficCount.merge(srcIp, 1, Integer::sum);

            // Print the packet info
            System.out.println("Packet: " + srcIp + " -> " + dstIp);

            // Detect high traffic
            if (trafficCount.get(srcIp) > TRAFFIC_THRESHOLD) {
                System.out.println("ALERT: High traffic detected from IP: " + srcIp);
            }

            detectPortScanning(srcIp, ipV4Packet);
            deepPacketInspection(packet);
            trackConnection(ipV4Packet);
        }

        // Check for TCP-specific information if available
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            System.out.println("TCP Packet: Src Port: " + srcPort + ", Dst Port: " + dstPort);
        }
    }

    private static void deepPacketInspection(Packet packet) {

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            byte[] payload = tcpPacket.getPayload() != null ? tcpPacket.getPayload().getRawData() : new byte[0];
            String payloadStr = new String(payload);

            if (payloadStr.contains("GET") || payloadStr.contains("POST")) System.out.println("HTTP packet: " + payloadStr);

            if (payloadStr.contains("SELECT") || payloadStr.contains("<script>")) System.out.println("ALERT: " + payloadStr);

            System.out.println(payloadStr);
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            byte[] payload = udpPacket.getPayload() != null ? udpPacket.getPayload().getRawData() : new byte[0];
            String payloadStr = new String(payload);

            if (payloadStr.contains("tunnel") || payloadStr.contains("malicious")) System.out.println("ALERT UDP: " + payloadStr);

            System.out.println(payloadStr);
        }
    }

    private static void detectPortScanning(String srcIp, IpV4Packet ipV4Packet) {
        TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);
        if (tcpPacket == null) return;

        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

        portScanTracker.putIfAbsent(srcIp, ConcurrentHashMap.newKeySet());
        portScanTracker.get(srcIp).add(dstPort);

        if (portScanTracker.get(srcIp).size() > 10) {
            System.out.println("ALERT: Potential port scanning activity from IP: " + srcIp);
        }
    }

    private static void trackConnection(IpV4Packet ipV4Packet) {
        TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            String connectionKey = srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort;


            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
            ConnectionState state = connectionTracker.getOrDefault(connectionKey, ConnectionState.NONE);
            System.out.println("Tracking connection for packet: " + connectionKey + " SYN: " + tcpHeader.getSyn() + " ACK: " + tcpHeader.getAck());

            switch (state) {
                case NONE:
                    if (tcpHeader.getSyn() && !tcpHeader.getAck()) {
                        connectionTracker.put(connectionKey, ConnectionState.SYN_SENT);
                        incompleteConnections.merge(srcIp, 1, Integer::sum);
                        System.out.println("Connection started: " + connectionKey);
                    }
                    break;
                case SYN_SENT:
                    if (tcpHeader.getSyn() && tcpHeader.getAck()) connectionTracker.put(connectionKey, ConnectionState.SYN_RECEIVED);
                    break;
                case SYN_RECEIVED:
                    if (tcpHeader.getAck()) {
                        connectionTracker.put(connectionKey, ConnectionState.ESTABLISHED);
                        incompleteConnections.merge(srcIp, -1, Integer::sum);
                        System.out.println("Connection established: " + connectionKey);
                    }
                    break;
                case ESTABLISHED:
                    if (tcpHeader.getFin()) {
                        connectionTracker.put(connectionKey, ConnectionState.FIN_WAIT);
                        System.out.println("Connection termination initiated: " + connectionKey);
                    }
                    break;
                case FIN_WAIT:
                    if (tcpHeader.getAck()) {
                        connectionTracker.put(connectionKey, ConnectionState.CLOSED);
                        System.out.println("Connection closed: " + connectionKey);
                    }
                    break;
            }

            if (incompleteConnections.getOrDefault(srcIp, 0) > 1) {
                System.out.println("ALERT: Potential SYN flood attack detected from IP: " + srcIp);
            }
        }
    }

    private enum ConnectionState {
        NONE,
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT,
        CLOSED
    }
}
