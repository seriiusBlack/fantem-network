from distutils.log import error
import socket
import threading
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.fernet import Fernet
from protocol import Packet, PacketManager
import os
import base64
import uuid

digest = hashes.Hash(hashes.SHA3_512())
digest.update(b"messge")
digest.finalize()

key = os.urandom(128) # keep secret
h = hmac.HMAC(key, hashes.SHA3_512())
h.update(b"message to bytes")
h.verify()
sig = h.finalize()


class Client:
    def __init__(self) -> None:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.signature = self.private_key.sign()
        self.server = None
        self.url = None
        self.packet = None
        # Keep key secret!!!!!
        self.key = Fernet.generate_key() # symetric cryptography
        self.f = Fernet(self.key)
        self.token = None

    
    def gen_token(self, data):
        self.token = self.f.encrypt(data)
        return 0

    def decrypt_token(self, token):
        data = self.f.decrypt(token)
        return (data, 0)

    def gen_req(self):
        pass

    def gen_packet(self):
        pass

    def sign(self, data):
        pass

    def verify(self, data, sig):
        status = self.public_key.verify(sig, data)
        if status != error:
            return (status, 0)
        else:
            return (status, -1)
    
    def generate_uuid(self):
        uid = uuid.uuid5(uuid.NAMESPACE_DNS, "{}.{}.{}".format())
        hex_id = uid.hex
        return (hex_id, 0)