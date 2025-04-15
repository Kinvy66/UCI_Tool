import uci
import re

class UCIPaser:
    def __init__(self):
        pass

    def __pre_process(self, packet: str) -> bytearray:
        # 去除字符串中可能存在的空格、0x前缀、换行等
        cleaned = re.sub(r'[ \n\t\r\x0b\x0c]|0x', '', packet.strip().lower())

        # 检查是否为有效的十六进制字符串
        if not re.fullmatch(r'^[0-9a-f]+$', cleaned):
            raise ValueError("Invalid hexadecimal string input")

        # 确保长度为偶数（每个字节需要两个十六进制字符）
        if len(cleaned) % 2 != 0:
            raise ValueError("Hex string must have an even number of characters")

        # 将十六进制字符串转换为bytearray
        try:
            return bytearray.fromhex(cleaned)
        except ValueError as e:
            raise ValueError(f"Failed to convert hex string to bytes: {str(e)}")

    def parser(self, packet: str):
        packet_bytes = self.__pre_process(packet)
        # print(packet_bytes)
        if len(packet_bytes) < 4:
            raise Exception("Not is a UCI Packet!!!")
        packet_parser = uci.ControlPacket.parse_all(packet_bytes)
        # print(packet_parser.show())
        return packet_parser.return_show()

def main():
    uci_parser = UCIPaser()
    print(uci_parser.parser('40020010000002000200020000064f53542d5632'))
    # uci_parser.parser('40020010000002000200020000064f53542d5632')
    # uci_parser.parser('20020000')
    pass

if __name__ == '__main__':
    main()


