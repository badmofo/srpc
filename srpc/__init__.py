import json
import struct
import socket
import SocketServer
import nacl.utils
from nacl.encoding import HexEncoder
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
        anti_replay_nonce, plaintext = plaintext[:16], plaintext[16:]
        message = json.loads(plaintext)
    except ValueError, e:
        raise SecureRpcException('decode error: invalid json')
    except CryptoError, e:
        raise SecureRpcException('decrypt error: %s' % e)
    return public_key_sender, anti_replay_nonce, message
    
def send_message(sock, message, anti_replay_nonce, private_key_sender, public_key_recipient):
    plaintext = anti_replay_nonce + json.dumps(message)
    box = Box(private_key_sender, public_key_recipient)
    ciphertext = box.encrypt(plaintext, nacl.utils.random(Box.NONCE_SIZE))
    public_key_sender = private_key_sender.public_key.encode()
    sock.sendall(struct.pack('!L', len(ciphertext)) + public_key_sender + ciphertext)

class SecureRpcRequest(object):
    def __init__(self, public_key, remote_addr):
        self.public_key = public_key
        self.remote_addr = remote_addr

def secure_rpc_serve(host, port, server_private_key, server_proxy):
    private_key = PrivateKey(server_private_key, HexEncoder)
    class MyTCPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            public_key, nonce, message = read_message(self.request, private_key)
            public_key_hex = public_key.encode(HexEncoder)
            request = SecureRpcRequest(public_key_hex, self.request.getpeername()[0])
            response = getattr(server_proxy, message['method'])(*([request] + message['params']))
            send_message(self.request, response, nonce, private_key, public_key)
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((host, port), MyTCPHandler)
    server.serve_forever()
    
class SecureRpcClient(object):
    def __init__(self, host, port, server_public_key, client_private_key):
        self.host = host
        self.port = port
        self.server_public_key = PublicKey(server_public_key, HexEncoder)
        self.client_private_key = PrivateKey(client_private_key, HexEncoder)

    def invoke(self, method, params, timeout=60):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        s.settimeout(timeout)
        request = {'method': method, 'params': params}
        nonce = nacl.utils.random(16)
        send_message(s, request, nonce, self.client_private_key, self.server_public_key)
        sender_public_key, response_nonce, response = read_message(s, self.client_private_key)
        if sender_public_key.encode(HexEncoder) != self.server_public_key.encode(HexEncoder):
            raise SecureRpcException('reply authentication error')
        if nonce != response_nonce:
            raise SecureRpcException('reply integrity error: replay suspected')
        return response
