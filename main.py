from PyQt6.QtWidgets import QApplication, QWidget
import sys
from PyQt6 import uic
from MainFormControl import MainFormControl

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainFormControl()
    w.show()
    sys.exit(app.exec())

