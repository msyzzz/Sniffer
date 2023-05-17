from unicodedata import name
from scapy.all import *
import time

class packetParser():
    def __init__(self) -> None:
        self.packTime = None
        self.lens = None
        self.packet = None
        self.layer1 = {'name' : None, 'src': None, 'dst': None,'info':None}
        self.layer2 = {'name' : None, 'src': None, 'dst': None,'version': None,\
            'ihl': None, 'tos': None, 'len': None, 'id': None, 'flag': None, 'chksum':None,\
            'opt':None, 'hwtype':None, 'ptype':None, 'hwlen':None,'type':None,'op':None,\
            'info':None, 'hwsrc':None, 'hwdst':None
            }
        self.layer3 = {'name':None, 'src': None, 'dst': None, 'seq':None, 'ack':None,\
            'dataofs':None, 'reserved':None, 'flag':None, 'len':None, 'chksum':None,\
            'type':None, 'code':None, 'id':None,'info':None, 'window':None
            }
        self.layer4 = {'name':None, 'info':None}
    
    def parse(self,packet,startTime):
        self.packTime = '{:.7f}'.format(time.time() - startTime)
        self.lens = str(len(packet))
        self.packet = packet
        self.parseLayer1(packet)
    
    def parseLayer1(self,packet):
        if packet.type == 0x800 or packet.type == 0x86dd or packet.type == 0x806:
            self.layer1['name'] = 'Ethernet'
            self.layer1['src'] = packet.src
            self.layer1['dst'] = packet.dst
            self.layer1['info'] = ('Ethernet, Src: '+ packet.src + ', Dst: '+packet.dst)
        elif packet.type == 0x2 or packet.type == 0x18:
            self.layer1['name'] = 'Loopback'
            self.layer1['info'] = 'Loopback'
        self.parseLayer2(packet)
        

    def parseLayer2(self,packet):
        if packet.type == 0x800 or packet.type == 0x2:
            self.layer2['name'] = 'IPv4'
            self.layer2['src'] = packet[IP].src
            self.layer2['dst'] = packet[IP].dst
            self.layer2['version'] = packet[IP].version
            self.layer2['ihl'] = packet[IP].ihl
            self.layer2['tos'] = packet[IP].tos
            self.layer2['len'] = packet[IP].len
            self.layer2['id'] = packet[IP].id
            self.layer2['flag'] = packet[IP].flags
            self.layer2['chksum'] = packet[IP].chksum
            self.layer2['opt'] = packet[IP].options
            self.layer2['info'] = ('IPv4, Src: '+packet[IP].src+', Dst: '+packet[IP].dst)
            self.parseLayer3(packet, 4)
        elif packet.type == 0x86dd or packet.type == 0x18:
            self.layer2['name'] = 'IPv6'
            self.layer2['src'] = packet[IPv6].src
            self.layer2['dst'] = packet[IPv6].dst
            self.layer2['version'] = packet[IPv6].version
            self.layer2['info'] = ('IPv6, Src: '+packet[IPv6].src+', Dst: '+packet[IPv6].dst)
            self.parseLayer3(packet, 6)
        elif packet.type == 0x806 : 
            self.layer2['name'] = 'ARP'
            self.layer2['src'] = packet[ARP].psrc
            self.layer2['dst'] = packet[ARP].pdst
            self.layer2['op'] = packet[ARP].op 
            self.layer2['hwtype'] = packet[ARP].hwtype
            self.layer2['ptype'] = packet[ARP].ptype
            self.layer2['hwlen'] = packet[ARP].hwlen
            self.layer2['len'] = packet[ARP].plen
            self.layer2['hwsrc'] = packet[ARP].hwsrc
            self.layer2['hwdst'] = packet[ARP].hwdst
            if packet[ARP].op == 1:
                self.layer2['info'] = ('Request: Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc))
            elif packet[ARP].op == 2:
                self.layer2['info'] = ('Reply: %s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc))
            else:
                self.layer2['info'] = ('Op: '+ packet[ARP].op )

    def parseLayer3(self,packet,num):
        if num == 4:
            if packet[IP].proto == 6:
                self.layer3['name'] = 'TCP'
                self.layer3['src'] = packet[TCP].sport
                self.layer3['dst'] = packet[TCP].dport
                self.layer3['seq'] = packet[TCP].seq
                self.layer3['ack'] = packet[TCP].ack
                self.layer3['window'] = packet[TCP].window
                self.layer3['dataofs'] = packet[TCP].dataofs
                self.layer3['reserved'] = packet[TCP].reserved
                self.layer3['flag'] = packet[TCP].flags
                self.layer3['info'] = ('Src Port: %s -> Dst Port: %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer4(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer4(packet, 6)
            elif packet[IP].proto == 17:
                self.layer3['name'] = 'UDP'
                self.layer3['src'] = packet[UDP].sport
                self.layer3['dst'] = packet[UDP].dport
                self.layer3['len'] = packet[UDP].len
                self.layer3['chksum'] = packet[UDP].chksum
                self.layer3['info'] =  ('Src Port: %s ->  Dst Port: %s Length: %s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
                if packet.haslayer('DNS'):
                    self.parseLayer4(packet, 7)
            elif packet[IP].proto == 1:
                self.layer3['name'] = 'ICMP'
                self.layer3['type'] = packet[ICMP].type
                self.layer3['code'] = packet[ICMP].code
                self.layer3['id'] = packet[ICMP].id
                self.layer3['chksum'] = packet[ICMP].chksum
                self.layer3['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer3['info'] = ('Echo (ping) request id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer3['info'] = ('Echo (ping) reply id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                else:
                    self.layer3['info'] = ('type: %s id: %s seq: %s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))      
            elif packet[IP].proto == 2:
                self.layer3['name'] = 'IGMP'
                self.layer3['len'] = packet[IPOption_Router_Alert].length
                self.layer3['info'] = ''
            else:
                self.layer3['name'] = str(packet[IP].proto)
                self.layer3['info'] = ''
        elif num == 6:
            if packet[IPv6].nh == 6:
                self.layer3['name'] = 'TCP'
                self.layer3['src'] = packet[TCP].sport
                self.layer3['dst'] = packet[TCP].dport
                self.layer3['seq'] = packet[TCP].seq
                self.layer3['ack'] = packet[TCP].ack
                self.layer3['window'] = packet[TCP].window
                self.layer3['dataofs'] = packet[TCP].dataofs
                self.layer3['reserved'] = packet[TCP].reserved
                self.layer3['flag'] = packet[TCP].flags
                self.layer3['info'] = ('Src Port: %s -> Dst Port: %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer4(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer4(packet, 6)
            elif packet[IPv6].nh == 17:
                self.layer3['name'] = 'UDP'
                self.layer3['src'] = packet[UDP].sport
                self.layer3['dst'] = packet[UDP].dport
                self.layer3['len'] = packet[UDP].len
                self.layer3['chksum'] = packet[UDP].chksum
                self.layer3['info'] =  ('Src Port: %s ->  Dst Port: %s Length: %s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))
                if packet.haslayer('DNS'):
                    self.parseLayer4(packet, 7)
            elif packet[IPv6].nh == 1:
                self.layer3['name'] = 'ICMP'
                self.layer3['type'] = packet[ICMP].type
                self.layer3['code'] = packet[ICMP].code
                self.layer3['id'] = packet[ICMP].id
                self.layer3['chksum'] = packet[ICMP].chksum
                self.layer3['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer3['info'] = ('Echo (ping) request id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer3['info'] = ('Echo (ping) reply id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                else:
                    self.layer3['info'] = ('type: %s id: %s seq: %s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))    
            elif packet[IPv6].nh == 2:
                self.layer3['name'] = 'IGMP'
                self.layer3['len'] = packet[IPOption_Router_Alert].length
                self.layer3['info'] = ''
            else:
                self.layer3['name'] = str(packet[IPv6].nh)
                self.layer3['info'] = ''

    def parseLayer4(self,packet,num):
        if num == 4:
            self.layer4['name'] ='HTTP'
            if packet.haslayer('HTTPRequest'):
                self.layer4['info'] = ('%s %s %s' % (packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'")))
            elif packet.haslayer('HTTPResponse'):
                self.layer4['info'] = ('%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'"))
             
        elif num ==6:
            self.layer4['name'] ='HTTPS'
            self.layer4['info'] = ('%s -> %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window))
        elif num == 7:
            self.layer4['name'] ='DNS'
            if packet[DNS].opcode == 0:
                tmp = '??'
                if packet[DNS].qd :
                    tmp = bytes.decode(packet[DNS].qd.qname)
                self.layer4['info'] = ('Src Port: %s ->  Dst Port: %s Length: %s DNS query: where %s ' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len,tmp))
            else:
                self.layer4['info'] = ('Src Port: %s ->  Dst Port: %s Length: %s DNS response' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len))


