from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP

data = 'abddelhadfsdf'
a = Ether() / IP(src='10.11.1.2', dst='10.11.1.1') / TCP() / Raw(load=data)
iface = IFACES.dev_from_name("veth0")
# a = Ether() / IP(src='192.168.1.68', dst='192.168.1.67') / TCP() / Raw(load=data)
# iface = IFACES.dev_from_name("enp3s0")
sendp(a, iface=iface)

