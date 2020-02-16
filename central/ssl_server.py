import json
import os
import ssl
import socket
import threading
from utils import recvall, database


def main(db):
    listen_addr = os.getenv('SSL_HOST', '127.0.0.1')
    listen_port = int(os.getenv('SSL_PORT', 8082))
    server_cert = os.getenv('SSL_CERT', './ssl/central.crt')
    server_key = os.getenv('SSL_KEY', './ssl/central.key')
    ca_cert = os.getenv('SSL_CA_CERT', './ssl/root_ca.crt')

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=ca_cert)

    bindsocket = socket.socket()
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(5)

    while True:
        newsocket, fromaddr = bindsocket.accept()
        conn = ssl.wrap_socket(newsocket, server_side=True, ca_certs=ca_cert, certfile=server_cert,
                               keyfile=server_key, cert_reqs=ssl.CERT_REQUIRED)
        try:
            x = threading.Thread(target=conn_handler, args=(1, conn, db))
            x.start()
            x.join()  # wait for thread to finish
        finally:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()


def conn_handler(name, conn, db):
    def tprint(*args, **kwargs):
        """Custom print function for threads"""
        print('___' + str(name) + " ".join(map(str, args)) + "XXX", **kwargs)

    tprint('Thread starting')
    try:
        buf = recvall(conn)
        data = json.loads(buf.decode())
        tprint(data)
        if data['operation'] == 'store':
            device = json.loads(data['data'])
            db.save_device(device)
            db.save_db()
    except:
        tprint("error")


if __name__ == '__main__':
    main()
