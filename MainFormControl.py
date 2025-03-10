from struct import Struct

from PyQt6.QtWidgets import QWidget, QMessageBox, QTableWidgetItem
from MainForm import Ui_Form
from construct import Struct, BitsInteger, Bytes, this


def control_packet_header(mt, pbf, gid, oid, payload):
    """
    命令包头
    :return:
    """
    msg_format = Struct(
        "mt" / BitsInteger(3),   # MT: 3 bits
        "pbf" / BitsInteger(1),  # PBF: 1 bit
        "gid" / BitsInteger(4),  # GID: 4 bits
        "rfu" / BitsInteger(2),  # RFU: 2 bits
        "oid" / BitsInteger(6),  # OID: 6 bits
        "length" / BitsInteger(8),  # Length: 8 bits
        "payload" / Bytes(this.length),  # Data: length bytes
    )

    msg = msg_format.build({
        "mt": mt,
        "pbf": pbf,
        "gid": gid,
        "rfu": 0x00,
        "oid": oid,
        "length": len(payload),
        "payload": payload,
    })
    msg = msg.hex()
    return  msg


class MainFormControl(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Form()
        self.ui.setupUi(self)
        self.payload = self.ui.groupBox_payload
        self.payloadTable = self.ui.tableWidget_payload
        self.MsgType = self.ui.comboBox_msgType
        self.PBF = self.ui.comboBox_PBF
        self.GID = self.ui.comboBox_GID
        self.OID = self.ui.comboBox_OID
        self.DPF = self.ui.comboBox_DPF
        self.Packets = self.ui.tableWidget_packets

        self.uci_core = ['CORE_DEVICE_RESET_CMD/RSP', 'CORE_DEVICE_STATUS_NTF','CORE_GET_DEVICE_INFO_CMD/RSP',
                         'CORE_GET_CAPS_INFO_CMD/RSP', 'CORE_SET_CONFIG_CMD/RSP', 'CORE_GET_CONFIG_CMD/RSP', 'RFU'
                         'CORE_GENERIC_ERROR_NTF', 'CORE_QUERY_UWBS_TIMESTAMP_CMD/RSP']
        self.uwb_session_config = ['SESSION_INIT_CMD/RSP'
                                    ,'SESSION_DEINIT_CMD/RSP'
                                    ,'SESSION_STATUS_NTF'
                                    ,'SESSION_SET_APP_CONFIG_CMD/RSP'
                                    ,'SESSION_GET_APP_CONFIG_CMD/RSP'
                                    ,'SESSION_GET_COUNT_CMD/RSP'
                                    ,'SESSION_GET_STATE_CMD/RSP'
                                    ,'SESSION_UPDATE_CONTROLLER_MULTICAST_LIST_CMD/RSP/NTF'
                                    ,'SESSION_UPDATE_DT_ANCHOR_RANGING_ROUNDS_CMD/RSP'
                                    ,'SESSION_UPDATE_DT_TAG_RANGING_ROUNDS_CMD/RSP'
                                    ,'RFU'
                                    , 'SESSION_QUERY_DATA_SIZE_IN_RANGING_CMD/RSP'
                                    , 'SESSION_SET_HUS_CONTROLLER_CONFIG_CMD/RSP'
                                    , 'SESSION_SET_HUS_CONTROLLER_CONFIG_CMD/RSP/NTF']
        self.uwb_session_control = ['SESSION_START_CMD/RSP/NTF'
                                    ,'SESSION_STOP_CMD/RSP'
                                    ,'RFU'
                                    ,'SESSION_GET_RANGING_COUNT_CMD/RSP'
                                    ,'SESSION_DATA_CREDIT_NTF'
                                    ,'SESSION_DATA_TRANSFER_STATUS_NTF'
                                    ,'SESSION_ROLE_CHANGE_NTF'
                                    ,'LOGICAL_LINK_CREATE_CMD/RSP/NTF'
                                    ,'LOGICAL_LINK_CLOSE_CMD/RSP'
                                    ,'LOGICAL_LINK_UWBS_CLOSE_NTF'
                                    ,'LOGICAL_LINK_UWBS_CREATE_NTF'
                                    ,'LOGICAL_LINK_GET_PARAM_CMD/RSP']
        self.test_group = ['TEST_CONFIG_SET_CMD/RSP'
                            ,'TEST_CONFIG_GET_CMD/RSP'
                            ,'TEST_PERIODIC_TX_CMD/RSP/NTF'
                            ,'TEST_PER_RX_CMD/RSP/NTF'
                            ,'RFU'
                            ,'TEST_RX_CMD/RSP/NTF'
                            ,'TEST_LOOPBACK_CMD/RSP/NTF'
                            ,'TEST_STOP_SESSION_CMD/RSP'
                            ,'TEST_SS_TWR_CMD/RSP/NTF'
                            ,'TEST_SR_RX_CMD/RSP/NTF']
        self.vendor_specific1 = []
        self.vendor_specific2 = []

        self.init_pushbutton_operator()
        self.init()

    def init(self):
        self.OID.addItems(self.uci_core)
        self.DPF.setEnabled(True)
        self.GID.setEnabled(False)
        self.OID.setEnabled(False)

    def init_pushbutton_operator(self):
        """
        连接按钮的槽函数
        :return:
        """
        self.ui.pushButton_add.clicked.connect(self.add_payload)
        self.ui.pushButton_delet.clicked.connect(self.delete_payload)
        self.GID.currentIndexChanged.connect(self.GID_change)
        self.MsgType.currentIndexChanged.connect(self.MsgType_change)
        self.ui.pushButton_save.clicked.connect(self.save_msg)

    def add_payload(self):
        row_count = self.payloadTable.rowCount()
        self.payloadTable.insertRow(row_count)
        # self.payloadTable.setItem(row_count, 0, QTableWidgetItem(f'数据{row_count + 1}-1'))
        # self.payloadTable.setItem(row_count, 1, QTableWidgetItem(f'数据{row_count + 1}-2'))
        # self.payloadTable.setItem(row_count, 2, QTableWidgetItem(f'数据{row_count + 1}-3'))

    def delete_payload(self):
        current_row = self.payloadTable.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, 'Warning', 'Please select a payload')
            return
        self.payloadTable.removeRow(current_row)

    def MsgType_change(self):
        """

        :return:
        """
        msgType = self.MsgType.currentIndex()
        if msgType != 0:
            self.DPF.setEnabled(False)
            self.GID.setEnabled(True)
            self.OID.setEnabled(True)
        else:
            self.DPF.setEnabled(True)
            self.GID.setEnabled(False)
            self.OID.setEnabled(False)

    def GID_change(self):
        """
        :return:
        """
        self.OID.clear()
        current_GID = self.GID.currentText()
        if current_GID == 'UCI Core':
            self.OID.addItems(self.uci_core)
        elif current_GID == 'UWB Session Config':
            self.OID.addItems(self.uwb_session_config)
        elif current_GID == 'UWB Session Control':
            self.OID.addItems(self.uwb_session_control)
        elif current_GID == 'Vendor Specific 1':
            self.OID.addItems(self.vendor_specific1)
        elif current_GID == 'Test Group':
            self.OID.addItems(self.test_group)
        elif current_GID == 'Vendor Specific 2':
            self.OID.addItems(self.vendor_specific2)

    def save_msg(self):
        """
        添加当前的
        :return:
        """
        mt = self.MsgType.currentIndex()
        pbf = self.PBF.currentIndex()
        # msg_value = 0x00

        current_pak_type = self.MsgType.currentIndex()
        if current_pak_type == 0:
            dpf = self.DPF.currentIndex()
        else:
            gid = self.GID.currentIndex()
            oid = self.OID.currentIndex()
            payload = self.read_payload()
            msg_value = control_packet_header(mt, pbf,gid, oid, payload)
        row_count = self.Packets.rowCount()
        self.Packets.insertRow(row_count)
        msg_name = self.OID.currentText()
        self.Packets.setItem(row_count, 0, QTableWidgetItem(msg_name))
        self.Packets.setItem(row_count, 1, QTableWidgetItem(msg_value))


    def data_packet_header(self, ):
        """
        数据包头
        :return:
        """

    def read_payload(self):
        """
        读取表格中的数据
        :return:
        """
        data = bytearray()

        for row in range(self.payloadTable.rowCount()):
            length_item = self.payloadTable.item(row, 1)
            value_item = self.payloadTable.item(row, 2)

            if length_item and value_item:
                length = int(length_item.text())
                value =  value_item.text()

                if value.startswith("0x"):
                    value_bytes = bytes.fromhex(value[2:])
                else:
                    value_bytes = value.encode('utf-8')
                if len(value_bytes) != length:
                    raise ValueError(f"Row {row + 1}: Data length mismatch")
                data.extend(value_bytes)
        return data


# 0000010000000000000000000001000000000000000001000155