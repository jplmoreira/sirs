# https://docs.python.org/3/library/socketserver.html
import os
import json
import ssl
import time
import socket
import threading
import socketserver

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

from utils import custom_protocol


def udp_discovery_broadcast(broadcast, host, port, location):
    def tprint(s):
        print("{}: {}".format(threading.current_thread().name, s))

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Enable port reusage so we will be able to run multiple clients and servers on single (host, port). 
    # Do not use socket.SO_REUSEADDR except you using linux(kernel<3.9): goto https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ for more information.
    # For linux hosts all sockets that want to share the same address and port combination must belong to processes that share the same effective user ID!
    # So, on linux(kernel>=3.9) you have to run multiple servers and clients under one user to share the same (host, port).
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Enable broadcasting mode
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    server.settimeout(0.2)
    # message = b"scan server discovery message"  # probably need to send the TCP info here
    data = {'host': host, 'port': port, 'location': location}
    message = json.dumps(data).encode()
    while True:
        server.sendto(message, (broadcast, 37020))
        tprint("discovery broadcast sent")
        time.sleep(30)


def main():
    HOST = os.getenv('SCAN_HOST', '127.0.0.1')
    PORT = int(os.getenv('SCAN_PORT', 9999))
    LOCATION = os.getenv('SCAN_LOCATION', 'scan server @ local network #1')
    BROADCAST = os.getenv('SCAN_BROADCAST', '255.255.255.255')

    # Create UDP thread that sends regular broadcasts for discovery of this server
    udp_thread = threading.Thread(target=udp_discovery_broadcast, args=(BROADCAST, HOST, PORT, LOCATION))
    # Exit the server thread when the main thread terminates
    udp_thread.daemon = True
    udp_thread.start()

    # https://www.bogotobogo.com/python/python_network_programming_socketserver_framework_for_network_servers_asynchronous_request_ThreadingMixIn_ForkingMixIn.php
    server = ThreadingTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:", server_thread.name)

    # ssl client
    # scan -> central

    while True:
        pass


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer): pass


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.


    self.request is the TCP socket connected to the client
    """

    host_addr = os.getenv('SSL_HOST', '127.0.0.1')
    host_port = int(os.getenv('SSL_PORT', 8082))
    client_cert = os.getenv('SSL_CLIENT_CERT', './ssl/scan-1.crt')
    client_key = os.getenv('SSL_CLIENT_KEY', './ssl/scan-1.key')
    ca_cert = os.getenv('SSL_CA_CERT', './ssl/root_ca.crt')

    def cur_thread(self):
        return threading.current_thread()

    def tprint(self, s):
        print("{}: {}".format(self.cur_thread(), s))

    def handle(self):

        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
        # load key
        with open(ThreadedTCPRequestHandler.client_key, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            self.tprint("private key length: " + str(private_key.key_size))

        # load certificate
        with open(ThreadedTCPRequestHandler.client_cert, "rb") as crt_file:
            # read certificate
            cert_b = crt_file.read()
            cert = x509.load_pem_x509_certificate(
                cert_b,
                default_backend()
            )
            print(cert.serial_number)

        protocol = custom_protocol.DHFernet()

        # send certificate
        self.request.sendall(cert.public_bytes(Encoding.PEM))

        # get peer_public_key and decrypt using certificate private key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption
        peer_public_key_ciphered = self.recvall()
        self.tprint("got peer_public_key_ciphered")

        peer_public_key = private_key.decrypt(
            peer_public_key_ciphered,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )

        protocol.set_peer_public_key(peer_public_key)

        # send DHFernet public_key signed with certificate private key
        public_key = protocol.get_public_key()
        signature = private_key.sign(
            public_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        msg = {'signature': signature.hex(), 'message': public_key.hex()}
        msg_str = json.dumps(msg).encode()
        self.request.sendall(msg_str)

        message = self.recvall()
        challenge_bytes = protocol.decrypt(message)
        self.tprint("[handshake] got challenge")

        challenge_int = int(challenge_bytes)
        response_int = challenge_int - 1
        response_bytes = str(response_int).encode()
        response = protocol.encrypt(response_bytes)
        self.request.sendall(response)
        self.tprint("[handshake] sent response")

        message = self.recvall()
        self.tprint("[handshake] got confirmation")
        confirm = protocol.decrypt(message)
        if confirm.decode() != "handshake ok":
            return False

        confirm = b"handshake ok"
        message = protocol.encrypt(confirm)
        self.request.sendall(message)
        self.tprint("got shared secret")  # protocol.shared_secret
        self.tprint("[handshake] done")

        while True:
            ciphertext = self.recvall()

            if ciphertext == b'':
                print("empty message, shutting down")
                return

            print("got message")
            message = protocol.decrypt(ciphertext)

            # send the message to the central server
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ThreadedTCPRequestHandler.ca_cert)
            context.load_cert_chain(certfile=ThreadedTCPRequestHandler.client_cert,
                                    keyfile=ThreadedTCPRequestHandler.client_key)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            central_conn = ssl.wrap_socket(s, server_side=False, ca_certs=ThreadedTCPRequestHandler.ca_cert,
                                           certfile=ThreadedTCPRequestHandler.client_cert,
                                           keyfile=ThreadedTCPRequestHandler.client_key, cert_reqs=ssl.CERT_REQUIRED)
            central_conn.connect((ThreadedTCPRequestHandler.host_addr, ThreadedTCPRequestHandler.host_port))

            msg_to_central = {'operation': 'store', 'data': message.decode()}
            data = json.dumps(msg_to_central).encode()
            central_conn.send(data)

    def recvall(self):
        BUFF_SIZE = 4096  # 4 KiB
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                # either 0 or end of data
                break
        return data


if __name__ == '__main__':
    main()
