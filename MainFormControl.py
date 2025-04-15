from PyQt6.QtWidgets import QWidget, QMessageBox, QTableWidgetItem
from MainForm import Ui_MainWindow
from construct import Struct, BitStruct, BitsInteger, Byte, Bytes, this
from uci_parser import UCIPaser

def control_packet_header(mt, pbf, gid, oid, payload):
    """
    命令包头
    """
    msg_format = Struct(
        "header" / BitStruct(
            "mt" / BitsInteger(3),   # MT: 3 bits
            "pbf" / BitsInteger(1),  # PBF: 1 bit
            "gid" / BitsInteger(4),  # GID: 4 bits
            "rfu" / BitsInteger(2),  # RFU: 2 bits
            "oid" / BitsInteger(6),  # OID: 6 bits
        ),
        "rfu1" / Byte,
        "length" / Byte,  # Length: 1 byte (instead of BitsInteger)
        "payload" / Bytes(this.length),  # Data: length bytes
    )

    msg = msg_format.build({
        "header": {
            "mt": mt,
            "pbf": pbf,
            "gid": gid,
            "rfu": 0x00,
            "oid": oid,
        },
        "rfu1": 0x00,
        "length": len(payload),
        "payload": payload,
    })
    msg_hex = msg.hex()
    return msg_hex



class MainFormControl(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
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
                         'CORE_GET_CAPS_INFO_CMD/RSP', 'CORE_SET_CONFIG_CMD/RSP', 'CORE_GET_CONFIG_CMD/RSP', 'RFU',
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
        self.ui.pushButton_deleteMsg.clicked.connect(self.delete_msg)
        # self.ui.pushButton_parser.clicked.connect(self.parser_cmd)
        self.ui.pushButton_parser.clicked.connect(self.uci_parser)

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
        msg_value = 0x00

        current_pak_type = self.MsgType.currentIndex()
        if current_pak_type == 0:
            dpf = self.DPF.currentIndex()
        else:
            gid = self.GID.currentIndex()
            if gid == 4:
                gid = 13
            oid = self.OID.currentIndex()
            payload = self.read_payload()
            msg_value = control_packet_header(mt, pbf,gid, oid, payload)
        row_count = self.Packets.rowCount()
        self.Packets.insertRow(row_count)
        msg_name = self.OID.currentText()
        self.Packets.setItem(row_count, 0, QTableWidgetItem(msg_name))
        self.Packets.setItem(row_count, 1, QTableWidgetItem(msg_value))

    def delete_msg(self):
        """

        :return:
        """
        current_row = self.Packets.currentRow()
        if current_row == -1:
            QMessageBox.warning(self, 'Warning', 'Please select a payload')
            return
        self.Packets.removeRow(current_row)


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
                    QMessageBox.warning(self, 'Warning', f"Row {row + 1}: Data length mismatch")
                    # raise ValueError(f"Row {row + 1}: Data length mismatch")
                data.extend(value_bytes)
        return data


    def parser_cmd(self):
        mt_list = ['CMD', 'RSP','NTF']
        cmd_str = self.ui.plainTextEdit_CMD.toPlainText()
        bytes_data = bytes.fromhex(cmd_str)
        if len(bytes_data) < 4:
            raise ValueError("CMD string must have at least 4 bytes (8 characters)")
            # 提取各个字节
        byte1 = bytes_data[0]  # 第一个字节
        byte2 = bytes_data[1]  # 第二个字节
        byte4 = bytes_data[3]  # 第四个字节

        MT = (byte1 >> 5) & 0b111
        PBF = (byte1 >> 4) & 0b1
        GID = byte1 & 0b1111
        OID = byte2 & 0b00111111
        payloadLen = byte4

        parser = ''

        if 0x00 == GID:
            parser = self.uci_core[OID]
        elif 0x01 == GID:
            parser = self.uwb_session_config[OID]
        elif 0x02 == GID:
            parser = self.uwb_session_control[OID]
        elif 0x0D == GID:
            parser = self.test_group[OID]

        parser = "MT:{mt} \r\nCMD: ".format(mt=mt_list[MT-1]) + parser
        self.ui.textEdit_cmd.setText(parser)


    def uci_parser(self):
        uci_parser = UCIPaser()
        cmd_str = self.ui.plainTextEdit_CMD.toPlainText()
        parser_str = uci_parser.parser(cmd_str)
        self.ui.textEdit_cmd.setText(parser_str)

# 0000010000000000000000000001000000000000000001000155
# 000_0_0100 00_000000 00000000 00010000 00000000 00000100 01 aa
# b'\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


"""
device cap

uint16_t max_data_mes_size;	// Maximum size of UCI Data Messages the UWBS can receive
uint16_t max_data_packet_payload_size; // Maximum UCI Data Packet Payload Size the UWBS can send or receive.
uint32_t fira_phy_version_range; // FiRa PHY version range supported,‘01010202’ = Version 1.1 to 2.2 support
uint32_t fira_mac_version_range;	// FiRa MAC version range supported,‘01010202’ = Version 1.1 to 2.2 support
uint8_t	 device_type;	// DC_DEVICE_TYPE_*
uint16_t device_roles;	// DC_DEVICE_ROLES_*
uint16_t ranging_method;	// DC_RANGING_METHOD_*
uint8_t  sts_config;	// DC_STS_CONFIG_*
uint8_t  multi_node_mode; // DC_MULTI_NODE_MODE_*
uint8_t  ranging_time_struct;	// DC_RANGING_TIME_*
uint8_t  schedule_mode;	// DC_SCHEDULE_MODE_*
uint8_t  hopping_mode;	// DC_HOPPING_MODE_*
uint8_t  block_striding;	// DC_BLOCK_STRIDING_*
uint8_t  uwb_init_time;
uint8_t  channels; // DC_CHANNELS_SUPPORT_*
uint8_t  rframe_config; // DC_RFRAME_CONFIG_*
uint8_t  cc_constr_len; // DC_CC_CONSTRAINT_LENGTH_K_*
uint8_t  bprf_para_sets; // DC_BPRF_PARAMETERS_SETS_*
uint8_t  hprf_para_sets[5]; // DC_HPRF_PARAMETERS_*_SETS_*
uint8_t  aoa_support; // DC_AOA_SUPPORT_*
uint8_t  extend_mac_address;
uint8_t  assigned;
uint8_t  session_key_len; // DC_SESSION_KEY_LENGTH_*
uint8_t  dt_anc_max_active_rr;
uint8_t  dt_tag_max_active_rr;
uint8_t  dt_tag_block_skipping;
uint8_t  psdu_len_support; // DC_PSDU_LENGTH_SUPPORT_*
"""