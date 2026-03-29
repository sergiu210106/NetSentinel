import asyncio
import json

# Configuration
HOST = '127.0.0.1'  # Localhost for testing
PORT = 9999

async def handle_client(reader, writer):
    """Handles incoming data from a single agent."""
    addr = writer.get_extra_info('peername')
    print(f"[+] New connection from {addr}")

    try:
        # Read data until a newline character is found
        while True:
            data = await reader.readline()
            if not data:
                break  # Connection closed

            try:
                # Decode and parse JSON
                packet_data = json.loads(data.decode())
                
                # Sprint 1 Checkpoint: Just print the data
                print(f"[RECEIVED] {packet_data}")
                
            except json.JSONDecodeError:
                print(f"[ERROR] Invalid JSON received from {addr}")
                
    except ConnectionResetError:
        print(f"[-] Connection lost from {addr}")
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[-] Disconnected from {addr}")

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    
    addr = server.sockets[0].getsockname()
    print(f"[*] Server listening on {addr}")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")