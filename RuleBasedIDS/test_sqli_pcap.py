import struct, time

def make_pcap(payload: bytes, fname="test_sqli.pcap"):
    # ------------ Ethernet Header ------------
    eth = (
        b'\xaa\xbb\xcc\xdd\xee\xff' +      # dst MAC
        b'\x11\x22\x33\x44\x55\x66' +      # src MAC
        struct.pack('!H', 0x0800)          # IPv4 EtherType
    )

    # ------------ IP Header ------------
    version_ihl = (4 << 4) + 5
    total_length = 20 + 20 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length,
        1234, 0, 64, 6, 0,
        struct.pack("!4B", 192,168,1,10),
        struct.pack("!4B", 192,168,1,100)
    )

    # ------------ TCP Header ------------
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        12345, 80, 0, 0,
        (5 << 4), 2, 8192, 0, 0
    )

    # ------------ Full Frame ------------
    frame = eth + ip_header + tcp_header + payload

    # ------------ PCAP Global Header ------------
    gh = struct.pack(
        "IHHIIII",
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
    )

    # ------------ Packet Header ------------
    ts = int(time.time())
    ph = struct.pack("IIII", ts, 0, len(frame), len(frame))

    with open(fname, "wb") as f:
        f.write(gh + ph + frame)

    print(f"[OK] PCAP generated → {fname}")


if __name__ == "__main__":
    payload = b"GET /index.php?id=1%20UNION%20SELECT%201,2,3 HTTP/1.1\r\nHost: test\r\n\r\n"
    make_pcap(payload)
