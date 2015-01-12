import sys
from srpc import secure_rpc_serve, SecureRpcClient

class Adder(object):
    def add(self, request, a, b):
        print request.public_key, request.remote_addr
        print 'adding', a, b
        return a + b
        
if sys.argv[1].startswith('s'):
    private_key = '1c5844eeb85c69711db9b588502f29655cb875d92eaa0240a55a7cea1260b944'
    secure_rpc_serve('localhost', 1234, private_key, Adder())
else:
    public_key = '0abcf909a59b1172b0d87f72e3d4feca40b931270b40ea546204c902b238aa22'
    private_key = '63f06156227b270225feacfc8f3374a8d5079c8deed1320d5db29a898f7a49d0'
    client = SecureRpcClient('localhost', 1234, public_key,  private_key)
    print client.invoke('add', [1,2])