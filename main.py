from PyQt6.QtWidgets import QApplication, QWidget
import sys
from PyQt6 import uic
from MainFormControl import MainFormControl

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainFormControl()
    w.show()
    sys.exit(app.exec())

# from construct import Struct, BitStruct, BitsInteger, Byte, Bytes, this
#
# def control_packet_header(mt, pbf, gid, oid, payload):
#     """
#     命令包头
#     """
#     msg_format = Struct(
#         "header" / BitStruct(
#             "mt" / BitsInteger(3),   # MT: 3 bits
#             "pbf" / BitsInteger(1),  # PBF: 1 bit
#             "gid" / BitsInteger(4),  # GID: 4 bits
#             "rfu" / BitsInteger(2),  # RFU: 2 bits
#             "oid" / BitsInteger(6),  # OID: 6 bits
#         ),
#         "length" / Byte,  # Length: 1 byte (instead of BitsInteger)
#         "payload" / Bytes(this.length),  # Data: length bytes
#     )
#
#     msg = msg_format.build({
#         "header": {
#             "mt": mt,
#             "pbf": pbf,
#             "gid": gid,
#             "rfu": 0x00,
#             "oid": oid,
#         },
#         "length": len(payload),
#         "payload": payload,
#     })
#     return msg.hex()
#
# # 测试
# mt = 1
# pbf = 0
# gid = 2
# oid = 0
# payload = b''
#
# result = control_packet_header(mt, pbf, gid, oid, payload)
# print(result)  # 预期输出 "220000"

