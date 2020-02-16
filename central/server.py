import sys
from threading import Thread

from flask import Flask, render_template, request, jsonify

from utils import database
from utils.config import Config
from central import ssl_server

app = Flask(__name__)
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None
app.config.from_object(Config)
db = None

@app.route('/')
def query():
    return render_template('query.html')


@app.route('/pass', methods=['POST'])
def passphrase():
    device_id = request.form['id']
    devices = []
    for device in db.devices:
        if device['id'] == device_id:
            devices.append(device)

    print("received: " + device_id)
    return jsonify(devices)


def main():
    Thread(target=ssl_server.main, args=(db,)).start()
    app.run(host='0.0.0.0', debug=False)


if __name__ == '__main__':
    db = database.Database()
    main()
