from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP, wrpcap

data = 'sCachorrod|00 00|E|00 00|E|00 00|@|00|dUSERdd'
a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / TCP(sport=2002, dport=21) / Raw(load=data)
# iface = IFACES.dev_from_name("veth0")
# a = Ether() / IP(src='192.168.1.68', dst='192.168.1.67') / TCP() / Raw(load=data)
# iface = IFACES.dev_from_name("enp3s0")
# sendp(a, iface=iface)
wrpcap('teste.pcap', a)
# data = 'taiguara'
# a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / TCP() / Raw(load=data)
# wrpcap('teste.pcap', a, append=True)

# data = 'pao'
# a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / UDP() / Raw(load=data)
# wrpcap('teste.pcap', a, append=True)
