"""
Modbus TCP Traffic Simulator
Generates synthetic Modbus TCP frames for lab testing and anomaly detection development.
"""

import socket
import struct
import time
import random
import argparse


# Modbus function codes
FC_READ_COILS = 0x01
FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10
# Suspicious function codes for anomaly testing
FC_READ_DEVICE_ID = 0x2B
FC_FORCE_LISTEN_MODE = 0x08


def build_modbus_frame(transaction_id: int, unit_id: int, function_code: int, data: bytes) -> bytes:
    """Build a Modbus TCP frame (MBAP header + PDU)."""
    pdu = struct.pack("B", function_code) + data
    mbap = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def simulate_normal_traffic(host: str, port: int, count: int, delay: float):
    """Simulate normal Modbus TCP read/write operations."""
    print(f"[*] Simulating normal Modbus traffic to {host}:{port}")

    for i in range(count):
        fc = random.choice([FC_READ_COILS, FC_READ_HOLDING_REGISTERS, FC_WRITE_SINGLE_REGISTER])
        data = struct.pack(">HH", random.randint(0, 100), random.randint(1, 10))
        frame = build_modbus_frame(i, unit_id=1, function_code=fc, data=data)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                s.sendall(frame)
                print(f"  [+] Frame {i:03d} | FC=0x{fc:02X} | {len(frame)} bytes")
        except (ConnectionRefusedError, socket.timeout):
            print(f"  [-] Frame {i:03d} | No listener at {host}:{port} (expected in lab)")

        time.sleep(delay)


def simulate_anomaly_traffic(host: str, port: int):
    """Simulate anomalous Modbus traffic for detection testing."""
    print(f"\n[!] Simulating anomalous Modbus traffic to {host}:{port}")

    anomalies = [
        ("Unauthorized function code", FC_READ_DEVICE_ID, struct.pack(">BB", 0x0E, 0x01)),
        ("Broadcast write attempt", FC_WRITE_MULTIPLE_REGISTERS, struct.pack(">HHB", 0, 10, 20) + b'\x00' * 20),
        ("Force listen mode", FC_FORCE_LISTEN_MODE, struct.pack(">HH", 0, 0)),
    ]

    for name, fc, data in anomalies:
        frame = build_modbus_frame(999, unit_id=255, function_code=fc, data=data)
        print(f"  [!] Anomaly: {name} | FC=0x{fc:02X} | {len(frame)} bytes")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                s.sendall(frame)
        except (ConnectionRefusedError, socket.timeout):
            pass
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description="Modbus TCP Traffic Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=502, help="Target port (default: 502)")
    parser.add_argument("--count", type=int, default=20, help="Number of normal frames (default: 20)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between frames in seconds")
    parser.add_argument("--anomalies", action="store_true", help="Include anomalous traffic")
    args = parser.parse_args()

    simulate_normal_traffic(args.host, args.port, args.count, args.delay)

    if args.anomalies:
        simulate_anomaly_traffic(args.host, args.port)

    print("\n[*] Simulation complete.")


if __name__ == "__main__":
    main()
