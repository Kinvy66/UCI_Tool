# Form implementation generated from reading ui file 'MainForm.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(982, 625)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.widget_2 = QtWidgets.QWidget(parent=Form)
        self.widget_2.setObjectName("widget_2")
        self.gridLayout = QtWidgets.QGridLayout(self.widget_2)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(parent=self.widget_2)
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.comboBox_msgType = QtWidgets.QComboBox(parent=self.widget_2)
        self.comboBox_msgType.setObjectName("comboBox_msgType")
        self.comboBox_msgType.addItem("")
        self.comboBox_msgType.addItem("")
        self.comboBox_msgType.addItem("")
        self.comboBox_msgType.addItem("")
        self.horizontalLayout.addWidget(self.comboBox_msgType)
        self.horizontalLayout_6.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(parent=self.widget_2)
        self.label_2.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.comboBox_PBF = QtWidgets.QComboBox(parent=self.widget_2)
        self.comboBox_PBF.setObjectName("comboBox_PBF")
        self.comboBox_PBF.addItem("")
        self.comboBox_PBF.addItem("")
        self.horizontalLayout_2.addWidget(self.comboBox_PBF)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.label_4 = QtWidgets.QLabel(parent=self.widget_2)
        self.label_4.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_11.addWidget(self.label_4)
        self.comboBox_DPF = QtWidgets.QComboBox(parent=self.widget_2)
        self.comboBox_DPF.setObjectName("comboBox_DPF")
        self.comboBox_DPF.addItem("")
        self.comboBox_DPF.addItem("")
        self.comboBox_DPF.addItem("")
        self.comboBox_DPF.addItem("")
        self.horizontalLayout_11.addWidget(self.comboBox_DPF)
        self.horizontalLayout_2.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_6.addLayout(self.horizontalLayout_2)
        self.verticalLayout.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtWidgets.QLabel(parent=self.widget_2)
        self.label_3.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.comboBox_GID = QtWidgets.QComboBox(parent=self.widget_2)
        self.comboBox_GID.setObjectName("comboBox_GID")
        self.comboBox_GID.addItem("")
        self.comboBox_GID.addItem("")
        self.comboBox_GID.addItem("")
        self.comboBox_GID.addItem("")
        self.comboBox_GID.addItem("")
        self.comboBox_GID.addItem("")
        self.horizontalLayout_3.addWidget(self.comboBox_GID)
        self.horizontalLayout_7.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_5 = QtWidgets.QLabel(parent=self.widget_2)
        self.label_5.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout_5.addWidget(self.label_5)
        self.comboBox_OID = QtWidgets.QComboBox(parent=self.widget_2)
        self.comboBox_OID.setObjectName("comboBox_OID")
        self.horizontalLayout_5.addWidget(self.comboBox_OID)
        self.horizontalLayout_7.addLayout(self.horizontalLayout_5)
        self.verticalLayout.addLayout(self.horizontalLayout_7)
        self.groupBox_payload = QtWidgets.QGroupBox(parent=self.widget_2)
        self.groupBox_payload.setObjectName("groupBox_payload")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.groupBox_payload)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.tableWidget_payload = QtWidgets.QTableWidget(parent=self.groupBox_payload)
        self.tableWidget_payload.setObjectName("tableWidget_payload")
        self.tableWidget_payload.setColumnCount(3)
        self.tableWidget_payload.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_payload.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_payload.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_payload.setHorizontalHeaderItem(2, item)
        self.verticalLayout_2.addWidget(self.tableWidget_payload)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.pushButton_add = QtWidgets.QPushButton(parent=self.groupBox_payload)
        self.pushButton_add.setObjectName("pushButton_add")
        self.horizontalLayout_4.addWidget(self.pushButton_add)
        self.pushButton_delet = QtWidgets.QPushButton(parent=self.groupBox_payload)
        self.pushButton_delet.setObjectName("pushButton_delet")
        self.horizontalLayout_4.addWidget(self.pushButton_delet)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.verticalLayout.addWidget(self.groupBox_payload)
        self.gridLayout.addLayout(self.verticalLayout, 0, 0, 1, 1)
        self.horizontalLayout_8.addWidget(self.widget_2)
        self.widget = QtWidgets.QWidget(parent=Form)
        self.widget.setObjectName("widget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.tableWidget = QtWidgets.QTableWidget(parent=self.widget)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        self.verticalLayout_3.addWidget(self.tableWidget)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.pushButton_save = QtWidgets.QPushButton(parent=self.widget)
        self.pushButton_save.setObjectName("pushButton_save")
        self.horizontalLayout_9.addWidget(self.pushButton_save)
        self.pushButton_edit = QtWidgets.QPushButton(parent=self.widget)
        self.pushButton_edit.setObjectName("pushButton_edit")
        self.horizontalLayout_9.addWidget(self.pushButton_edit)
        self.verticalLayout_3.addLayout(self.horizontalLayout_9)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.pushButton_deleteMsg = QtWidgets.QPushButton(parent=self.widget)
        self.pushButton_deleteMsg.setObjectName("pushButton_deleteMsg")
        self.horizontalLayout_10.addWidget(self.pushButton_deleteMsg)
        self.pushButton_export = QtWidgets.QPushButton(parent=self.widget)
        self.pushButton_export.setObjectName("pushButton_export")
        self.horizontalLayout_10.addWidget(self.pushButton_export)
        self.verticalLayout_3.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_8.addWidget(self.widget)
        self.horizontalLayout_8.setStretch(0, 5)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "UCI Tool"))
        self.label.setText(_translate("Form", "Message Type : "))
        self.comboBox_msgType.setItemText(0, _translate("Form", "Data Packet"))
        self.comboBox_msgType.setItemText(1, _translate("Form", "Command Message"))
        self.comboBox_msgType.setItemText(2, _translate("Form", "Response Message"))
        self.comboBox_msgType.setItemText(3, _translate("Form", "Notification Message"))
        self.label_2.setText(_translate("Form", "PBF : "))
        self.comboBox_PBF.setItemText(0, _translate("Form", "0b0 Complete"))
        self.comboBox_PBF.setItemText(1, _translate("Form", "0b1 Segement"))
        self.label_4.setText(_translate("Form", "DPF : "))
        self.comboBox_DPF.setItemText(0, _translate("Form", "DATA_MESSAGE_SND"))
        self.comboBox_DPF.setItemText(1, _translate("Form", "DATA_MESSAGE_RCV"))
        self.comboBox_DPF.setItemText(2, _translate("Form", "LL_DATA_MESSAGE_SND"))
        self.comboBox_DPF.setItemText(3, _translate("Form", "LL_DATA_MESSAGE_RCV"))
        self.label_3.setText(_translate("Form", "GID : "))
        self.comboBox_GID.setItemText(0, _translate("Form", "UCI Core"))
        self.comboBox_GID.setItemText(1, _translate("Form", "UWB Session Config"))
        self.comboBox_GID.setItemText(2, _translate("Form", "UWB Session Control"))
        self.comboBox_GID.setItemText(3, _translate("Form", "Vendor Specific 1"))
        self.comboBox_GID.setItemText(4, _translate("Form", "Test Group"))
        self.comboBox_GID.setItemText(5, _translate("Form", "Vendor Specific 2"))
        self.label_5.setText(_translate("Form", "OID : "))
        self.groupBox_payload.setTitle(_translate("Form", "Payload"))
        item = self.tableWidget_payload.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Payload Field"))
        item = self.tableWidget_payload.horizontalHeaderItem(1)
        item.setText(_translate("Form", "Length"))
        item = self.tableWidget_payload.horizontalHeaderItem(2)
        item.setText(_translate("Form", "Value"))
        self.pushButton_add.setText(_translate("Form", "添加"))
        self.pushButton_delet.setText(_translate("Form", "删除"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Name"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Form", "Value"))
        self.pushButton_save.setText(_translate("Form", "保存"))
        self.pushButton_edit.setText(_translate("Form", "编辑"))
        self.pushButton_deleteMsg.setText(_translate("Form", "删除"))
        self.pushButton_export.setText(_translate("Form", "导出"))
