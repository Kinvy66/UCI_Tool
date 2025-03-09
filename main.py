from PyQt6.QtWidgets import QApplication, QWidget
import sys
from PyQt6 import uic
from MainFormContrl import MainFormContrl

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainFormContrl()
    w.show()
    sys.exit(app.exec())