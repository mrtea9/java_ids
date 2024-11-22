package com.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;

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

    private static final Map<String, Integer> trafficCount = new ConcurrentHashMap<>();
    private static final Map<String, Set<Integer>> portScanTracker = new ConcurrentHashMap<>();
    private static final ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

    public static void main( String[] args ) {
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(0);
            if (nif == null) {
                System.out.println("No network interface found");
                return;
            }
            System.out.println("Listening on interface " + nif.getName());

            PcapHandle handle = nif.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

            Map<String, Integer> trafficCount = new HashMap<>();

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
        }

        // Check for TCP-specific information if available
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            System.out.println("TCP Packet: Src Port: " + srcPort + ", Dst Port: " + dstPort);
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
}
