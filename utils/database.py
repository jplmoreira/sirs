import os
import json
from cryptography.fernet import Fernet


class Database:
    """ sqn """
    filename = "db.json.fernet"

    def __init__(self):
        self.devices = []
        self.key = None

        self.load_key()
        self.load_db()

        self.fernet = Fernet(self.key)

    # TODO: arranjar maneira de guardar a chave
    def save_key(self):
        self.key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(self.key)

    def load_key(self):
        print("reading database key from disk")
        if os.path.exists("key.key"):
            self.key = open("key.key", "rb").read()
        else:
            self.save_key()

    def save_device(self, device):
        self.devices.append(device)

    def save_db(self):
        fernet = Fernet(self.key)
        db = {'devices': self.devices}
        json_data = json.dumps(db).encode()
        encrypted_json_data = fernet.encrypt(json_data)

        with open(Database.filename, "wb+") as f:
            print("writing database data to disk")
            f.write(encrypted_json_data)

    def load_db(self):
        print("reading database data from disk")

        if os.path.isfile(Database.filename):
            fernet = Fernet(self.key)
            with open(Database.filename, "rb") as file:
                encrypted_json_str = file.read()
            json_str = fernet.decrypt(encrypted_json_str)
            json_obj = json.loads(json_str)

            self.devices = json_obj['devices']
            print(self.devices)
