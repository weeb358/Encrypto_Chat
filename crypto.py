#Cipher class for AES, DES, and RSA encryption/decryption

from Crypto.Cipher import AES, DES  
from Crypto.PublicKey import RSA  
from Crypto.Cipher import PKCS1_OAEP  
from Crypto.Random import get_random_bytes  
from Crypto.Util.Padding import pad, unpad  
import base64  

class Cipher:
    def __init__(self):  
        self.rsa_keys = RSA.generate(2048)  
        self.public_key = self.rsa_keys.publickey().export_key()  
        self.private_key = self.rsa_keys.export_key()  

    def encrypt_aes(self, message, key):  
        cipher = AES.new(key, AES.MODE_CBC)  
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))  
        iv = base64.b64encode(cipher.iv).decode('utf-8')  
        ct = base64.b64encode(ct_bytes).decode('utf-8')  
        return iv, ct 

    def decrypt_aes(self, iv, ct, key):  
        iv = base64.b64decode(iv)  
        ct = base64.b64decode(ct) 
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)  
        pt = unpad(cipher.decrypt(ct), AES.block_size)  
        return pt.decode('utf-8')  
    def encrypt_des(self, message, key):  
        cipher = DES.new(key, DES.MODE_CBC)  
        ct_bytes = cipher.encrypt(pad(message.encode(), DES.block_size))  
        iv = base64.b64encode(cipher.iv).decode('utf-8')  
        ct = base64.b64encode(ct_bytes).decode('utf-8')  
        return iv, ct  

    def decrypt_des(self, iv, ct, key):  
        iv = base64.b64decode(iv)  
        ct = base64.b64decode(ct)  
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)  
        pt = unpad(cipher.decrypt(ct), DES.block_size)  
        return pt.decode('utf-8') 

    def encrypt_rsa(self, message, public_key):  
        recipient_key = RSA.import_key(public_key) 
        cipher = PKCS1_OAEP.new(recipient_key)  
        ct = base64.b64encode(cipher.encrypt(message.encode())).decode('utf-8')  
        return ct  

    def decrypt_rsa(self, ct):  
        cipher = PKCS1_OAEP.new(RSA.import_key(self.private_key))  
        pt = cipher.decrypt(base64.b64decode(ct)).decode('utf-8')  
        return pt  
    
