import asyncio
import os
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import threading
import time

class Server:
    def __init__(self, host: str, port: int, cache_timeout: int = 300, db_path: str = os.getcwd()):
        self.clients = set()
        # Assume Session is a custom class you've defined elsewhere for session management
        self.session = Session(is_server=True, cache_threshold=cache_timeout, path=db_path)
        self.stop_flag = threading.Event()

        # Generate server keys for secure communication
        self.server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
        server_public_key = self.server_private_key.public_key()
        self.server_public_key_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Set up the server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.server_socket.setblocking(False)
        
        # Server start message (Consider adding a print or logging statement here)
        print(f"Server started and listening on {host}:{port}")

        # Start the server's main loop in a separate thread
        main_thread = threading.Thread(target=self.run_thread)
        main_thread.start()

    def run_thread(self):
        asyncio.run(self.server_main_loop())

    async def server_main_loop(self):
        while not self.stop_flag.is_set():
            try:
                client_socket, client_address = await self.loop.sock_accept(self.server_socket)
                self.loop.create_task(self.setup_client(client_socket, client_address))
            except asyncio.CancelledError:
                break  # Server was stopped

    async def setup_client(self, client_socket: socket.socket, client_address):
        try:
            client_public_key_bytes = await self.loop.sock_recv(client_socket, 1024)
            client_public_key = serialization.load_pem_public_key(client_public_key_bytes, default_backend())
            await self.loop.sock_sendall(client_socket, self.server_public_key_bytes)
            
            shared_secret = self.server_private_key.exchange(ec.ECDH(), client_public_key)
            kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session key", backend=default_backend())
            key = kdf.derive(shared_secret)
            f = Fernet(base64.urlsafe_b64encode(key))

            # Process the client's requests in a separate task
            self.loop.create_task(self.main_client_loop(client_socket, f))
        except ConnectionResetError:
            pass  # Handle client disconnection

    async def main_client_loop(self, client_socket: socket.socket, encryption: Fernet):
        try:
            while not self.stop_flag.is_set():
                request = await self.loop.sock_recv(client_socket, 4096)  # Adjust buffer size as needed
                if not request:
                    break  # Client disconnected
                
                # Decrypt the request, process it, and prepare the response
                decrypted_request = encryption.decrypt(request)
                # Process the decrypted request here...
                
                # Encrypt and send the response
                encrypted_response = encryption.encrypt(b'Response')  # Replace with actual response
                await self.loop.sock_sendall(client_socket, encrypted_response)
        finally:
            client_socket.close()

# Example usage
if __name__ == "__main__":
    server = Server('localhost', 8888)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Server shutting down...")
