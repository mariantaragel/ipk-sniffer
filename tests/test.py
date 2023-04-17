import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
import scapy.contrib.igmp

def send_igmp():
    send(IP(dst="127.0.0.1")/scapy.contrib.igmp.IGMP()/Raw(load="igmp"))
    print("Packet type = IGMP")

def send_udp(port):
    send(IP(dst="127.0.0.1")/UDP(dport=port)/Raw(load="udp"))
    print("Packet type = UDP")

def send_tcp(port):
    send(IP(dst='127.0.0.1')/TCP(dport=port)/Raw(load="tcp"))
    print("Packet type = TCP")

def send_icmp4():
    send(IP(dst="127.0.0.1")/ICMP()/Raw(load="icmp4"))
    print("Packet type = ICMpv4")

def send_mld():
    send(IPv6(dst="::1")/scapy.layers.inet6.ICMPv6MLQuery()/Raw(load="mld"))
    print("Packet type = ICMPv6 MLD")

def send_ndp():
    send(IPv6(dst="::1")/scapy.layers.inet6.ICMPv6ND_NS()/Raw(load="ndp"))
    print("Packet type = ICMPv6 NDP")

def send_arp():
    send(ARP(pdst="127.0.0.1")/Raw(load="arp"))
    print("Packet type = ARP")

def test_tcp():
    send_tcp(53)
    send_igmp()
    send_tcp(53)

def test_udp():
    send_tcp(53)
    send_udp(123)

def test_multicast():
    send_igmp()
    send_icmp4()
    send_mld()

def test_icmp():
    send_igmp()
    send_icmp4()

def test_arp():
    send_tcp(53)
    send_arp()

def test_num_opt():
    send_udp(123)
    send_igmp()

def test_port():
    send_udp(22)
    send_mld()
    send_tcp(22)

def test_empty_cli():
    send_arp()