from distutils.log import error
import socketserver
import threading
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.fernet import Fernet
import base64
import uuid
from protocol import Packet
import time 

    # Responsible for protocol layer.
class ThreadedFantemRequestHandler(socketserver.BaseRequestHandler):

    def setup(self):
        # Called before the handle() method to perform any initialization actions required. The default implementation does nothing.
        pass


    def handle(self):
        # Must do all the work required to service a request. The default implementation does nothing. Serveral instance attributes are aviailable to it; self.request; self.client_address; self.server
        # self.server: top access top-level server info
        print("initiating connection from client {}".format(self.client_address))
        self.thread = threading.Thread()
        request =  self.request.recv(4096).strip()
        decoded_request = base64.b64decode(request.split())
        request_packet = Packet()
        request_packet.url = decoded_request[0]
        request_packet.headers = decoded_request[1]
        print(self.client_address + "sent {}".format(request_packet))
        print("Generating a response packet. . .")
        response_packet = Packet()
        response_packet.data = "Whats gucci"
        encoded_request = base64.b64encode(response_packet)
        response = encoded_request
        print("Sending response to client {}".format(self.client_address))
        self.request.sendall(response)

    def finish(self):
        # Called after the handle() method to perform any clean up actions required. The default implementation does nothing. If setup() reaises an exception, this function will not be called.
        pass

    # Responsible for communication layer

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
class ThreadedFantemServer(ThreadingTCPServer):

    def __init__(self) -> None:
        super().__init__()
        self.sys_admin_kill = None
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.key = None
        self.msg_sig = None
        self.signature = None
    
# One-Way Hashing Section:
    def packet_hasher(self):
        self.packet = Packet()
        hash_digest = hashes.Hash(hashes.SHA3_512())
        hash_digest.update(b"{url_hash}"+b"{headers_hash}"+b"{msg_hash}"+b"{data_hash}"+b"{sig_hash}"+b"{uuid_hash}".format(self.packet.url, self.packet.headers, self.packet.message, self.packet.data, self.packet.signature, self.packet.unique_id))
        self.packet.hash_id = hash_digest.finalize()
        return self.packet.hash_id

# Hash-based Message Authentication Codes Section:
    def gen_key(self):
        self.key = os.urandom(128) 
        return self.key

    def gen_hmac(self):
        self.hmac = hmac.HMAC(self.key, hashes.SHA3_512())
        return 0

    def update_hmac(self, data):
        return self.hmac.update(data)
    
    def gen_msgSig(self):
        self.msg_sig = self.hmac.finalize()
        return self.msg_sig
    
    def verify_msgSig(self, sig):
        return self.hmac.verify(sig)
    
# Symmetric Encryption Section:
    def gen_sym_key(self):
        symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(symmetric_key)

    def encrypt(self, data):
        self.token = self.fernet.encrypt(data)
        return self.token

    def decrypt(self, token):
        return self.fernet.decrypt(token)

# Asymmetric Encryption Section:
    def sign(self, data):
        self.signature = self.private_key.sign(data)
        return self.signature
    
    def verify(self, data, signature):
        status = self.public_key.verify(signature, data)
        if status != error:
            return (status, 0)
        else:
            return (status, -1)

    def service_actions(self) -> None:
        
        return super().service_actions()

    def verify_request(self, request, client_address) -> bool:

        return super().verify_request(request, client_address)
    
    def process_request(self, request, client_address) -> None:
        return super().process_request(request, client_address)

    def gen_unique_id(self):
        uid = uuid.uuid5(uuid.NAMESPACE_DNS, str(os.urandom(128)))
        self.packet.unique_id = uid


if __name__ == "__main__ ":
    HOST = 'localhost'
    PORT = 8029
    with ThreadedFantemServer((HOST, PORT), ThreadedFantemRequestHandler) as fantem_server:
        fantem_server.sys_admin_kill = 0
        fantem_server.allow_reuse_address = True
        fantem_server.request_queue_size = 250
        print("Initiating fantem server. . .")
        time.sleep(1)
        print(". . .")
        time.sleep(3)
        print(". . .")
        print("Fantem Server available @{}".format(fantem_server.server_address))
        fantem_server.serve_forever()


        if fantem_server.sys_admin_kill != 0:
            print("Closing fantem server")
            fantem_server.shutdown()
            fantem_server.server_close()




# HMAC: Data Authentication
# HASH Functions: Data Integrity