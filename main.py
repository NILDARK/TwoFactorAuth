from Ui_Login import Ui_loginSection
from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
import sys


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = QWidget()
    ui = Ui_loginSection()
    ui.setupUi(win)
    win.show()
    sys.exit(app.exec_())
