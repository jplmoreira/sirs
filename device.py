import json
import os
import re
import socket
import time
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import custom_protocol, recvall


def prepare_handshake(passphrase, mac_address, location, ca_cert):
    with open(ca_cert, "rb") as file:
        root_ca_crt: x509.Certificate = x509.load_pem_x509_certificate(
            file.read(),
            default_backend()
        )

    id_salt = b'z\x1cK\x021\xf5K\xc8\xd1\x1aw<\x1c\xed\x97\x08\x11\xbaO\xdc\xea?\x96\x8c\xd5\xc1\xc5\xe3g\x97\xc3\xdb'
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(id_salt)
    digest.update(mac_address.encode())
    digest.update(bytes(passphrase, encoding='utf-8'))
    user_identifier = digest.finalize().hex()

    # derive
    # Salts should be randomly generated
    # salt = b'.\x0b5i|\xb1\x9d\xd9\xae\x9e\xad\xf61*8R'
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(bytes(passphrase, encoding='utf-8'))

    # encrypt
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CTR
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
    to_cipher = {'id': user_identifier, 'location': location, 'mac': mac_address,
                 'timestamp': str(time.time())}
    print("got data to cipher")
    plaintext = json.dumps(to_cipher).encode()

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    to_send = {'kdf_salt': salt.hex(), 'aes_ctr_nonce': nonce.hex(), 'ciphertext': ciphertext.hex(),
               'id': user_identifier}
    print(to_send)
    print("got data to send")

    # decrypt
    # nonce = ct[:16]
    # content = ct[16:]
    # decipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    # decryptor = decipher.decryptor()
    # print(decryptor.update(content) + decryptor.finalize())
    return root_ca_crt, to_send


def do_handshake(root_ca_crt, to_send, HOST, PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        protocol = custom_protocol.DHFernet()

        # get certificate
        crt_b = recvall(sock)
        print("[handshake] got scan certificate")

        crt: x509.Certificate = x509.load_pem_x509_certificate(crt_b, default_backend())

        if crt is None:
            print("[handshake error] expected certificate, got something else")
            return False

        try:
            # verify certificate
            # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.tbs_certificate_bytes
            root_ca_crt.public_key().verify(
                crt.signature,
                crt.tbs_certificate_bytes,
                # Depends on the algorithm used to create the certificate
                padding.PKCS1v15(),
                crt.signature_hash_algorithm,
            )
            # TODO: verificar not_valid_{after,before}
        except InvalidSignature:
            print("[handshake error] invalid certificate signature")
            return False

        print("[handshake] certificate ok")

        # cipher DHFernet public key with certificate public key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
        ciphertext = crt.public_key().encrypt(
            protocol.get_public_key(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )

        sock.sendall(ciphertext)
        print("[handshake] sent DH public key")

        # get peer_public_key signed with certificate private key ( and nonce - 1 )
        message = recvall(sock)
        message_json = json.loads(message.decode())
        signature = message_json['signature']
        message_content = message_json['message']

        try:
            crt.public_key().verify(
                bytes.fromhex(signature),
                bytes.fromhex(message_content),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("[handshake error] invalid signature")
            return False

        print("[handshake] got DH public key")

        # decipher with certificate public key and DHFernet calculate shared secret key
        protocol.set_peer_public_key(bytes.fromhex(message_content))
        print("[handshake] got shared secret")

        random_challenge = os.urandom(16)
        challenge_int = int.from_bytes(random_challenge, byteorder='little')
        challenge = str(challenge_int)
        message = protocol.encrypt(challenge.encode())
        sock.sendall(message)

        message = recvall(sock)
        response = protocol.decrypt(message)
        response_int = int(response.decode())

        if response_int != (challenge_int - 1):
            print("[handshake error] failed challenge")
            return False

        print("[handshake] challenge response ok")

        confirm = b"handshake ok"
        message = protocol.encrypt(confirm)
        sock.sendall(message)

        message = recvall(sock)
        print("[handshake] got confirmation")
        confirm = protocol.decrypt(message)
        if confirm.decode() != "handshake ok":
            return False
        print("[handshake] done")

        # send mac address encrypted with passphrase
        ct = json.dumps(to_send)

        print("sending ct")
        message = protocol.encrypt(ct.encode())
        sock.sendall(message)

        return True


def udp_recv_broadcast():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP

    # Enable port reusage so we will be able to run multiple clients and servers on single (host, port). 
    # Do not use socket.SO_REUSEADDR except you using linux(kernel<3.9): goto https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ for more information.
    # For linux hosts all sockets that want to share the same address and port combination must belong to processes that share the same effective user ID!
    # So, on linux(kernel>=3.9) you have to run multiple servers and clients under one user to share the same (host, port).
    # Thanks to @stevenreddie
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Enable broadcasting mode
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    client.bind(("", 37020))
    print("waiting for udp broadcast...")
    while True:
        message, addr = client.recvfrom(1024)
        print(message)
        try:
            data = json.loads(message.decode())
            return data['host'], data['port'], data['location']
        except:
            return None, None


def main():

    passphrase = ""
    mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    print("MAC Address:", mac_address)

    # setup
    while len(passphrase) < 16:
        passphrase = input('[>16 chars] passphrase: ')

    HOST, PORT, LOCATION = udp_recv_broadcast()
    ca_cert = os.getenv("CA_CERT", './ssl/root_ca.crt')
    root_ca_crt, to_send = prepare_handshake(passphrase, mac_address, LOCATION, ca_cert)

    if HOST and PORT:
        do_handshake(root_ca_crt, to_send, HOST, PORT)


if __name__ == '__main__':
    main()
