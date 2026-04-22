from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

######### RSA ENCRYPTION SCHEME HERE #########   

def generateKeyPair(username):
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(encoding = serialization.Encoding.PEM, format = "PEM", encryption_algorithm = serialization.NoEncryption())
    public_key_bytes = public_key.public_bytes(encoding = serialization.Encoding.PEM, format = "PEM", encryption_algorithm = serialization.NoEncryption())

    with open("./server/server_private.pem".format(username), "wb") as file:
        file.write(private_key_bytes)  
        
    with open("./client/client_public.pem".format(username), "wb") as file:
        file.write(public_key_bytes)        

#################### END ####################