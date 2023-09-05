A simple RPC client/server package that uses PyNaCL to secure communications.

**WARNING:** USE THIS CODE AT YOUR OWN RISK.  IT HAS BEEN NEITHER REVIEWED OR THOROUGHLY TESTED AND CURRENTLY HAS KNOWN ISSUED RELATED TO FORWARD SECRECY.

To generate keypairs for use with this library use:
```python
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder

pk = PrivateKey.generate()
print('Private: ' + pk.encode(HexEncoder).decode('utf8'))
print('Public:  ' + pk.public_key.encode(HexEncoder).decode('utf8'))
```
