from PyQt5.QtWidgets import *
from sniffer import *
from snifferGUI import *
import time
from packetParser import *

class SnifferController():
    def __init__(self,ui):
        self.ui = ui
        self.sniffer = None
        self.getInterfaces()
        self.setConnection()

    def getInterfaces(self):
        interfaces = []
        for i in repr(conf.route).split('\n')[1:]:
            tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]',i).group()[0:44].rstrip()
            if len(tmp)>0:
                interfaces.append(tmp)
        interfaces = list(set(interfaces))
        interfaces.sort()
        self.ui.setInterfaces(interfaces)
    
    def setConnection(self):
        self.ui.buttonStart.clicked.connect(self.start)    
        self.ui.buttonPause.clicked.connect(self.stop)
        self.ui.tableWidget.itemClicked.connect(self.ui.showDetail)
        self.ui.buttonRe.clicked.connect(self.ui.clear)
    
    def start(self):
        self.ui.interface = self.ui.Interfaces.currentText()
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.sniffer.interface = self.ui.Interfaces.currentText()
            self.sniffer.HandleSignal.connect(self.parse)
            self.sniffer.start()
            print('start sniffing')
        elif self.sniffer.conditionFlag :
            if self.ui.interface != self.ui.Interfaces.currentText() :
                self.sniffer.interface = self.ui.Interfaces.currentText()
                self.ui.clear()
            self.sniffer.resume()

    def stop(self):
        self.sniffer.pause()
    
    def parse(self,pac):
        res = []
        packets = packetParser()
        packets.parse(pac,self.ui.startTime)
        res.append(packets.packTime)
        res.append(packets.layer2['src'])
        res.append(packets.layer2['dst'])
        type = None
        info = None
        if packets.layer4['name'] is not None:
            type = packets.layer4['name']
            info = packets.layer4['info']
        elif packets.layer3['name'] is not None:
            type = packets.layer3['name']
            info = packets.layer3['info']
        elif packets.layer2['name'] is not None:
            type = packets.layer2['name']
            info = packets.layer2['info']
        res.append(type)
        res.append(packets.lens)
        res.append(info)
        res.append(packets)
        self.ui.setTableItems(res)
 
