"""
Sprint 2 - Task 2.3: Server with ML Inference
Extends the Sprint 1 TCP listener to classify every received packet
using ThreatDetector and log the result to the console.
"""

import asyncio
import json

from threat_detector import ThreatDetector

# ── Configuration ───────────────────────────────────────────────────────────
HOST = '127.0.0.1'
PORT = 9999

# ── Global detector instance (loaded once at startup) ───────────────────────
detector = ThreatDetector()


def log_prediction(packet_data: dict, label: str, confidence: float) -> None:
    """Formats and prints a classification result to the console."""
    src = packet_data.get("src_ip", "unknown")
    dst = packet_data.get("dst_ip", "unknown")
    proto = packet_data.get("protocol", "?")
    port  = packet_data.get("dst_port", "?")
    size  = packet_data.get("size", 0)
    pct   = f"{confidence * 100:.1f}%"

    if label == "Malicious":
        print(
            f"[ALERT] Malicious traffic detected | "
            f"{src} → {dst}:{port} | {proto} | {size}B | confidence: {pct}"
        )
    else:
        print(
            f"[INFO]  Normal traffic             | "
            f"{src} → {dst}:{port} | {proto} | {size}B | confidence: {pct}"
        )


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handles incoming data from a single agent connection."""
    addr = writer.get_extra_info('peername')
    print(f"[+] New connection from {addr}")

    try:
        while True:
            data = await reader.readline()
            if not data:
                break  # Agent disconnected

            try:
                packet_data = json.loads(data.decode())
            except json.JSONDecodeError:
                print(f"[ERROR] Invalid JSON received from {addr}")
                continue

            # ── Sprint 2: classify instead of just printing ─────────────
            try:
                label, confidence = detector.predict(packet_data)
                log_prediction(packet_data, label, confidence)
            except Exception as e:
                print(f"[ERROR] Prediction failed: {e}")
                print(f"        Raw packet: {packet_data}")

    except ConnectionResetError:
        print(f"[-] Connection lost from {addr}")
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[-] Disconnected from {addr}")


async def main():
    # Load the model before accepting any connections
    detector.load_model()

    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr   = server.sockets[0].getsockname()
    print(f"[*] NetSentinel server listening on {addr}")
    print(f"[*] ThreatDetector ready — waiting for packets...\n")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
