import scapy.layers.l2
import scapy.layers.inet
import scapy.layers.inet6
import scapy.packet
import scapy.utils
import time

# pkt1: Basic TCP Packet (SYN)
pkt1 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.1", dst="10.0.0.1", ttl=64, tos=0) / scapy.layers.inet.TCP(sport=12345, dport=80, flags="S", window=8192) / scapy.packet.Raw(load="Hello")
pkt1.time = time.time()

# pkt2: Short Packet (Fixed length, no IP)
pkt2 = scapy.layers.l2.Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff", type=0x0800) / scapy.packet.Raw(load="ShortPacket")
if len(pkt2) < 26:
    pkt2 = pkt2 / scapy.packet.Raw(load="\x00" * (26 - len(pkt2)))  # Pad to 26 bytes if needed

# pkt3: Large Payload (No SYN)
pkt3 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.1", dst="10.0.0.1") / scapy.layers.inet.TCP(sport=12345, dport=80, flags=0) / scapy.packet.Raw(load="A" * 100)
pkt3.time = pkt2.time + 0.001

# pkt4: Multiple Packets (No SYN)
pkt4 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.1", dst="10.0.0.1") / scapy.layers.inet.TCP(sport=12345, dport=80, flags=0) / scapy.packet.Raw(load="Packet2")
pkt4.time = pkt3.time + 0.001

# pkt5: Multiple Packets (No SYN)
pkt5 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.1", dst="10.0.0.1") / scapy.layers.inet.TCP(sport=12345, dport=80, flags=0) / scapy.packet.Raw(load="Packet3")
pkt5.time = pkt4.time + 0.001

# pkt6: UDP Packet
pkt6 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.2", dst="10.0.0.2") / scapy.layers.inet.UDP(sport=1234, dport=53) / scapy.packet.Raw(load="DNSQuery")
pkt6.time = pkt5.time + 0.001

# pkt7: Payload Value Filter (No SYN)
pkt7 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.1", dst="10.0.0.1") / scapy.layers.inet.TCP(sport=12345, dport=80, flags=0) / scapy.packet.Raw(load=b"\xDE\xAD\xBE\xEF" + b"ExtraData")
pkt7.time = pkt6.time + 0.001

# pkt8: VLAN-tagged TCP Packet (SYN+ACK)
pkt8 = scapy.layers.l2.Ether() / scapy.layers.l2.Dot1Q(vlan=100) / scapy.layers.inet.IP(src="192.168.1.3", dst="10.0.0.3") / scapy.layers.inet.TCP(sport=54321, dport=443, flags="SA") / scapy.packet.Raw(load="VLANTest")
pkt8.time = pkt7.time + 0.001

# pkt9: Double VLAN Tags (QinQ)
pkt9 = scapy.layers.l2.Ether() / scapy.layers.l2.Dot1Q(vlan=200) / scapy.layers.l2.Dot1Q(vlan=300) / scapy.layers.inet.IP(src="192.168.1.4", dst="10.0.0.4") / scapy.layers.inet.UDP(sport=5678, dport=1234) / scapy.packet.Raw(load="DoubleVLAN")
pkt9.time = pkt8.time + 0.001

# pkt10: ICMP Echo Request
pkt10 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.5", dst="10.0.0.5") / scapy.layers.inet.ICMP(type=8, code=0) / scapy.packet.Raw(load="PingData")
pkt10.time = pkt9.time + 0.001

# pkt11: ARP Request
pkt11 = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.layers.l2.ARP(op=1, psrc="192.168.1.6", pdst="192.168.1.7")
pkt11.time = pkt10.time + 0.001

# pkt12: IPv6 with ICMPv6
pkt12 = scapy.layers.l2.Ether() / scapy.layers.inet6.IPv6(src="2001:db8::1", dst="2001:db8::2") / scapy.layers.inet6.ICMPv6EchoRequest(data="IPv6Ping")
pkt12.time = pkt11.time + 0.001

# pkt13: VLAN-tagged ICMP
pkt13 = scapy.layers.l2.Ether() / scapy.layers.l2.Dot1Q(vlan=400) / scapy.layers.inet.IP(src="192.168.1.8", dst="10.0.0.8") / scapy.layers.inet.ICMP(type=0, code=0) / scapy.packet.Raw(load="VLANPingReply")
pkt13.time = pkt12.time + 0.001

# pkt14: Modbus TCP Request (Read Holding Registers, Function Code 3)
pkt14 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="192.168.1.10", dst="10.0.0.10") / scapy.layers.inet.TCP(sport=54321, dport=502, flags="PA") / scapy.packet.Raw(load=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")
pkt14.time = pkt13.time + 0.001

# pkt15: Modbus TCP Response
pkt15 = scapy.layers.l2.Ether() / scapy.layers.inet.IP(src="10.0.0.10", dst="192.168.1.10") / scapy.layers.inet.TCP(sport=502, dport=54321, flags="PA") / scapy.packet.Raw(load=b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x12\x34")
pkt15.time = pkt14.time + 0.001

# Write to PCAP
packets = [pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11, pkt12, pkt13, pkt14, pkt15]
scapy.utils.wrpcap("test_extended.pcap", packets)
print("Generated test_extended.pcap with 15 packets")