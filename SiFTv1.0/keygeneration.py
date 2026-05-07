#python3

import os
from Crypto.PublicKey import RSA

def generateKeyPair():
    key = RSA.generate(2048)

    private_pem = key.export_key('PEM')
    public_pem = key.publickey().export_key('PEM')

    base = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(base, 'server', 'server_private.pem'), 'wb') as f:
        f.write(private_pem)

    with open(os.path.join(base, 'client', 'server_public.pem'), 'wb') as f:
        f.write(public_pem)

    print('RSA key pair generated.')
    print('  Private key -> server/server_private.pem')
    print('  Public key  -> client/server_public.pem')

if __name__ == '__main__':
    generateKeyPair()
