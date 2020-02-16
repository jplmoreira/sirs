# https://docs.python.org/3/library/socketserver.html

import socketserver
import threading
from utils import custom_protocol
from central.server import CentralServerMessageHandler


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.


    self.request is the TCP socket connected to the client
    """

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

    def handle(self):
        cur_thread = threading.current_thread()
        central_server = CentralServerMessageHandler()

        def tprint(s):
            print("{}: {}".format(cur_thread.name, s))

        protocol = custom_protocol.DHFernet()

        # get Bob's public key  (also calculates shared secret)
        peer_public_key = self.recvall()
        protocol.set_peer_public_key(peer_public_key)

        # send Alice's public key
        public_key = protocol.get_public_key()
        self.request.sendall(public_key)

        while True:
            ciphertext = self.recvall()

            if ciphertext == b'':
                print("empty message, shutting down")
                return

            tprint("encrypted: " + str(ciphertext))

            message = protocol.decrypt(ciphertext)

            tprint("decrypted: " + str(message))

            if message == "exit":
                tprint("Ending connection...")
                return
            else:
                central_server.handle_message(message)
