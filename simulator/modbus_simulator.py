"""
Modbus TCP Traffic Simulator
Generates synthetic Modbus TCP frames for lab testing and anomaly detection development.
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import time

from src.logger import setup_logger


# Modbus function codes
FC_READ_COILS = 0x01
FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLES_REGISTERS = 0x10
# Suspicious function codes for anomaly testing
FC_READ_DEVICE_ID = 0x2B
FC_FORCE_LISTEN_MODE = 0x08


def build_modbus_frame(transaction_id: int, unit_id: int, function_code: int, data: bytes) -> bytes:
    """
    Build a Modbus TCP frame (MBAP header + PDU).
    """
    pdu = struct.pack("B", function_code) + data
    mbap = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


class ModbusSimulator:
    """
    Simple Modbus TCP traffic simulator with structured logging.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.logger = setup_logger("ModbusSimulator")
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        """
        Establish a TCP connection to the Modbus server.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)

        self.sock.connect((self.host, self.port))
        self.logger.info(f"Connected to {self.host}:{self.port}")

    def disconnect(self) -> None:
        """
        Close the TCP connection if it is open.
        """
        if self.sock is not None:
            try:
                self.sock.close()
                self.logger.info("Disconnected from Modbus server")
            finally:
                self.sock = None

    def send_frame(self, frame: bytes, description: str = "") -> None:
        """
        Send a Modbus frame on the active connection and log a hex dump.
        """
        if self.sock is None:
            raise RuntimeError("Socket is not connected. Call connect() first.")

        self.sock.sendall(frame)
        hex_dump = frame.hex()
        if description:
            self.logger.info(f"{description} | {len(frame)} bytes | {hex_dump}")
        else:
            self.logger.info(f"Frame sent | {len(frame)} bytes | {hex_dump}")

    def simulate_normal_traffic(self, count: int, delay: float) -> None:
        """
        Simulate normal Modbus TCP read/write operations.
        """
        self.logger.info(
            f"Simulating normal Modbus traffic to {self.host}:{self.port} "
            f"({count} frames, delay={delay}s)"
        )

        for i in range(count):
            fc = random.choice(
                [FC_READ_COILS, FC_READ_HOLDING_REGISTERS, FC_WRITE_SINGLE_REGISTER]
            )
            data = struct.pack(">HH", random.randint(0, 100), random.randint(1, 10))
            frame = build_modbus_frame(i, unit_id=1, function_code=fc, data=data)

            try:
                self.connect()
                self.send_frame(frame, description=f"Normal frame {i:03d} | FC=0x{fc:02X}")
            except (ConnectionRefusedError, socket.timeout) as exc:
                self.logger.warning(
                    f"Normal frame {i:03d} failed: no listener at "
                    f"{self.host}:{self.port} ({exc!r})"
                )
            finally:
                self.disconnect()

            time.sleep(delay)

    def simulate_anomaly_traffic(self) -> None:
        """
        Simulate anomalous Modbus traffic for detection testing.
        """
        self.logger.info(
            f"Simulating anomalous Modbus traffic to {self.host}:{self.port}"
        )

        anomalies = [
            (
                "Unauthorized function code",
                FC_READ_DEVICE_ID,
                struct.pack(">BB", 0x0E, 0x01),
            ),
            (
                "Broadcast write attempt",
                FC_WRITE_MULTIPLES_REGISTERS,
                struct.pack(">HHB", 0, 10, 20) + b"\x00" * 20,
            ),
            (
                "Force listen mode",
                FC_FORCE_LISTEN_MODE,
                struct.pack(">HH", 0, 0),
            ),
        ]

        for name, fc, data in anomalies:
            frame = build_modbus_frame(
                transaction_id=999, unit_id=255, function_code=fc, data=data
            )
            try:
                self.connect()
                self.send_frame(
                    frame,
                    description=f"Anomaly: {name} | FC=0x{fc:02X}",
                )
            except (ConnectionRefusedError, socket.timeout) as exc:
                self.logger.warning(
                    f"Anomaly frame '{name}' failed: no listener at "
                    f"{self.host}:{self.port} ({exc!r})"
                )
            finally:
                self.disconnect()

            time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus TCP Traffic Simulator")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=502,
        help="Target port (default: 502)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of normal frames (default: 20)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between frames in seconds",
    )
    parser.add_argument(
        "--anomalies",
        action="store_true",
        help="Include anomalous traffic",
    )

    args = parser.parse_args()

    simulator = ModbusSimulator(args.host, args.port)
    simulator.simulate_normal_traffic(args.count, args.delay)

    if args.anomalies:
        simulator.simulate_anomaly_traffic()

    print("\n[*] Simulation complete.")


if __name__ == "__main__":
    main()

