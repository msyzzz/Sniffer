from PyQt5 import QtCore,QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from scapy.all import *
import time

class SnifferGui(object):
    def setupUi(self, MainWindow):
        self.MainWindow = MainWindow
        self.startTime = None
        self.interface = None
        self.packets = []
        global counts
        global displays
        counts = 0
        displays = 0
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1920,1080)
        MainWindow.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayoutBar = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayoutBar.setObjectName("gridLayoutBar")
        self.gridLayoutMainShow = QtWidgets.QGridLayout()
        self.gridLayoutMainShow.setObjectName("gridLayoutMainShow")

        self.textBrowserShow = QtWidgets.QTextBrowser(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setVerticalStretch(1)
        self.textBrowserShow.setSizePolicy(sizePolicy)
        self.textBrowserShow.setObjectName("textBrowserShow")
        self.gridLayoutMainShow.addWidget(self.textBrowserShow, 2, 0, 1, 1)

        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setVerticalStretch(1)
        self.treeWidget.setSizePolicy(sizePolicy)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.headerItem().setText(0, "root")
        self.gridLayoutMainShow.addWidget(self.treeWidget, 1, 0, 1, 1)

        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setVerticalStretch(2)
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(6, item)
        self.gridLayoutMainShow.addWidget(self.tableWidget, 0, 0, 1, 1)

        self.gridLayoutBar.addLayout(self.gridLayoutMainShow, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)

        self.toolbar = QtWidgets.QToolBar(MainWindow)
        self.toolbar.setObjectName("toolbar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolbar)
        self.Interfaces = QComboBox()
        self.toolbar.addWidget(self.Interfaces)
        self.toolbar.addSeparator()

        self.buttonStart = QtWidgets.QPushButton()
        self.buttonStart.setIcon(QIcon("./static/start.png"))
        self.buttonStart.setToolTip("开始捕获")
        self.toolbar.addWidget(self.buttonStart)
        self.toolbar.addSeparator()

        self.buttonPause = QtWidgets.QPushButton()
        self.buttonPause.setIcon(QIcon("./static/pause.png"))
        self.buttonPause.setToolTip("暂停捕获")
        self.toolbar.addWidget(self.buttonPause)
        self.toolbar.addSeparator()

        self.buttonRe = QtWidgets.QPushButton()
        self.buttonRe.setIcon(QIcon("./static/reset.png"))
        self.buttonRe.setToolTip("清空列表")
        self.toolbar.addWidget(self.buttonRe)
        self.toolbar.addSeparator()
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Sniffer"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "序号"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "时间"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "源地址"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "目的地址"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "协议"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "长度"))
        item = self.tableWidget.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "详情"))
        self.toolbar.setWindowTitle(_translate("MainWindow", "tools"))

        self.tableWidget.horizontalHeader().setSectionsClickable(False)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.setColumnWidth(0,60)
        self.tableWidget.setColumnWidth(5,60)
        self.tableWidget.setColumnWidth(6,1000)
        self.tableWidget.verticalHeader().setVisible(False)
        self.treeWidget.setHeaderHidden(True)
        self.treeWidget.setColumnCount(1)

    def setInterfaces(self,c):
        self.Interfaces.addItems(c)

    def setTableItems(self,res):
        global counts
        global displays
        counts += 1
        displays = counts
        if res :
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(counts)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(res[0]))
            self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(res[1]))
            self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(res[2]))
            self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(res[3]))
            self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(res[4]))
            self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(res[5]))
            self.packets.append(res[6])
    
    def setInfo(self,row,times):
        num = self.tableWidget.item(row,0).text()
        Time = self.tableWidget.item(row,1).text()
        length = self.tableWidget.item(row,5).text()
        interface = self.interface
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(times))
        Frame = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Frame.setText(0,'Frame %s: %s bytes on %s' % (num,length,interface))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0,'Interface: %s' % interface)
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0,'Arrival Time: %s' % timeformat)
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0,'Time since reference or first frame: %s' % Time)
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0,'Frame Number: %s' % num)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0,'Frame Length: %s' % length)

    def showDetail(self):
        row = self.tableWidget.currentRow()
        packet = self.packets[row]
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)
        self.setInfo(row,packet.packet.time) 
        self.setLayer1(packet)
        self.setLayer2(packet)
        if packet.layer3['name'] is not None:
            self.setLayer3(packet)
        if packet.layer4['name'] is not None:
            self.setLayer4(packet)
        self.textBrowserShow.clear()
        content = hexdump(packet.packet,dump=True)
        self.textBrowserShow.append(content)

    def clear(self):
        global counts
        global displays
        counts = 0
        displays = 0
        self.tableWidget.setRowCount(0)
        self.treeWidget.clear()
        self.textBrowserShow.clear()
        self.packets = []
    

    def setLayer1(self,packet):
        if packet.layer1['name']  == 'Ethernet':
            Ethernet_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Ethernet_.setText(0,packet.layer1['info'])
            EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetDst.setText(0,'Dst: '+ packet.layer1['dst'])
            EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetSrc.setText(0,'Src: '+ packet.layer1['src'])
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetType.setText(0,'Type: '+ packet.layer2['name'])
        elif packet.layer1['name']  == 'Loopback':
            Loopback_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Loopback_.setText(0,packet.layer1['info'])
            LoopbackType = QtWidgets.QTreeWidgetItem(Loopback_)
            LoopbackType.setText(0,'Type: '+ packet.layer2['name'])
        
    def setLayer2(self,packet):
        if packet.layer2['name'] == 'IPv4':
            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0,packet.layer2['info'])
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0,'Version: %s'% packet.layer2['version'])
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0,'Header Length: %s' % packet.layer2['ihl'])
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0,'Tos: %s'% packet.layer2['tos'])
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0,'Total Length: %s' % packet.layer2['len'])
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0,'Identification: %s' % packet.layer2['id'])
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0,'Flags: %s' % packet.layer2['flag'])
            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0,'Checksum: 0x%x' % packet.layer2['chksum'])
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0,'Src: %s' % packet.layer2['src'])
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0,'Dst: %s' % packet.layer2['dst'])
            IPv4Options = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Options.setText(0,'Options: %s' % packet.layer2['opt'])
            IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Proto.setText(0,'Protocol: %s' % packet.layer3['name'])
        elif packet.layer2['name'] == 'IPv6':
            IPv6_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv6_.setText(0, packet.layer2['info'])
            IPv6Version = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Version.setText(0,'Version: %s'% packet.layer2['version'])
            IPv6Src = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Src.setText(0,'Src: %s' % packet.layer2['src'])
            IPv6Dst = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Dst.setText(0,'Dst: %s' % packet.layer2['dst'])
            IPv6Proto = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Proto.setText(0,'Protocol: '+ packet.layer3['name'])
        elif packet.layer2['name'] == 'ARP':
            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0, packet.layer2['name'] + " "+ packet.layer2['info'])
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0,'Hardware Type: 0x%x' % packet.layer2['hwtype'])
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0,'Protocol Type: 0x%x' % packet.layer2['ptype'])
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0,'Hardware Size: %s' % packet.layer2['hwlen'])
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0,'Protocol Size: %s' % packet.layer2['len'])
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            arpOp.setText(0,'Opcode:  %s' % packet.layer2['info'])
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0,'Sender MAC: %s' % packet.layer2['hwsrc'])
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0,'Sender IP Addeess: %s' % packet.layer2['src'])
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0,'Target MAC: %s' % packet.layer2['hwdst'])
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0,'Target IP Address: %s' % packet.layer2['dst'])

    def setLayer3(self,packet):
        if packet.layer3['name'] == 'TCP':
            tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            tcp.setText(0, packet.layer3['info'])
            tcpSport = QtWidgets.QTreeWidgetItem(tcp)
            tcpSport.setText(0,'Src Port: %s' % packet.layer3['src'])
            tcpDport = QtWidgets.QTreeWidgetItem(tcp)
            tcpDport.setText(0,'Dst Port: %s' % packet.layer3['dst'])
            tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
            tcpSeq.setText(0,'Sequence Number: %s' % packet.layer3['seq'])
            tcpAck = QtWidgets.QTreeWidgetItem(tcp)
            tcpAck.setText(0,'Acknowledge Number: %s' % packet.layer3['ack'])
            tcpWindow = QtWidgets.QTreeWidgetItem(tcp)
            tcpWindow.setText(0,'Window: %s' % packet.layer3['window'])
            tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
            tcpFlags.setText(0,'Flags: %s' % packet.layer3['flag'])
        elif packet.layer3['name'] == 'UDP':
            udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            udp.setText(0,packet.layer3['info'])
            udpSport = QtWidgets.QTreeWidgetItem(udp)
            udpSport.setText(0,'Src Port: %s' % packet.layer3['src'])
            udpDport = QtWidgets.QTreeWidgetItem(udp)
            udpDport.setText(0,'Dst Port: %s' % packet.layer3['dst'])
            udpLen = QtWidgets.QTreeWidgetItem(udp)
            udpLen.setText(0,'Length: %s' % packet.layer3['len'])
            udpChksum = QtWidgets.QTreeWidgetItem(udp)
            udpChksum.setText(0,'Checksum: 0x%x' % packet.layer3['chksum'])
        elif packet.layer3['name'] == 'ICMP':
            icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            icmp.setText(0,'ICMP')
            icmpType = QtWidgets.QTreeWidgetItem(icmp)
            icmpType.setText(0,'Type: %s' % packet.layer3['info'])
            icmpCode = QtWidgets.QTreeWidgetItem(icmp)
            icmpCode.setText(0,'Code: %s' % packet.layer3['code'])
            icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
            icmpChksum.setText(0,'Checksum: 0x%x' % packet.layer3['chksum'])
            icmpId = QtWidgets.QTreeWidgetItem(icmp)
            icmpId.setText(0,'Number: %s' % packet.layer3['id'])
        elif packet.layer3['name'] == 'IGMP':
            igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            igmp.setText(0,packet.layer3['info'])
            igmpLength = QtWidgets.QTreeWidgetItem(igmp)
            igmpLength.setText(0,'length: %s' % packet.layer3['len'])
        else:
            waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
            waitproto.setText(0,'Protocol  %s' % packet.layer3['name'])
            waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
            waitprotoInfo.setText(0,packet.layer3['info'])

    def setLayer4(self,packet):
        waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
        waitproto.setText(0, packet.layer4['name'])
        waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
        waitprotoInfo.setText(0,packet.layer4['info'])

        
    



