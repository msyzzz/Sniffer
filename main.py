from snifferGUI import *
from snifferController import *
from sniffer import *
import sys
import os

if __name__ == "__main__":
        os.chdir(sys.path[0])
        app = QtWidgets.QApplication(sys.argv)
        ui = SnifferGui()
        MainWindow = QtWidgets.QMainWindow()
        ui.setupUi(MainWindow)
        MainWindow.show()
        sc = SnifferController(ui)
        sys.exit(app.exec_())