import json
import struct
import socket
import SocketServer
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError

MAX_MESSAGE_SIZE = 1024 * 1024

class SecureRpcException(Exception):
    pass

def read_message(sock, private_key):
    size = struct.unpack('!L', sock.recv(4))[0]
    if size > MAX_MESSAGE_SIZE:
        raise SecureRpcException('transport error: invalid message size %s' % size)
    public_key_sender = sock.recv(32)
    if len(public_key_sender) != 32:
        raise SecureRpcException('transport error: public key not full read')
    public_key_sender = PublicKey(public_key_sender)
    ciphertext = sock.recv(size)
    if len(ciphertext) != size:
        raise SecureRpcException('transport error: message not fully read')
    try:
        box = Box(private_key, public_key_sender)
        plaintext = box.decrypt(ciphertext)
        message = json.loads(plaintext)
    except ValueError, e:
        raise SecureRpcException('decode error: invalid json')
    except CryptoError, e:
        raise SecureRpcException('decrypt error: %s' % e)
    return public_key_sender, message
    
def send_message(sock, message, private_key_sender, public_key_recipient):
    plaintext = json.dumps(message)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    box = Box(private_key_sender, public_key_recipient)
    ciphertext = box.encrypt(plaintext, nonce)
    public_key_sender = private_key_sender.public_key.encode()
    sock.sendall(struct.pack('!L', len(ciphertext)) + public_key_sender + ciphertext)

def secure_rpc_serve(host, port, server_private_key, server_proxy):
    private_key = PrivateKey(server_private_key.decode('hex'))
    class MyTCPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            public_key, message = read_message(self.request, private_key)
            public_key_hex = public_key.encode().encode('hex')
            response = getattr(server_proxy, message['method'])(*([public_key_hex] + message['params']))
            send_message(self.request, response, private_key, public_key)
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((host, port), MyTCPHandler)
    server.serve_forever()
    
class SecureRpcClient(object):
    def __init__(self, host, port, server_public_key, client_private_key):
        self.host = host
        self.port = port
        self.server_public_key = PublicKey(server_public_key.decode('hex'))
        self.client_private_key = PrivateKey(client_private_key.decode('hex'))

    def invoke(self, method, params, timeout=60):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        s.settimeout(timeout)
        request = {'method': method, 'params': params}
        send_message(s, request, self.client_private_key, self.server_public_key)
        return read_message(s, self.client_private_key)
