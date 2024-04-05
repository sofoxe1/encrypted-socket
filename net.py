import lzma
import pickle
import base64
import socket
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHAKE256,BLAKE2b,SHA512,SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.Random import get_random_bytes
from os.path import exists
import threading
import time
import sys
import sqlite3
#checksum(1B),l_data(4B),2B reserved,(data,nonce)

nonce_len=12
tag_len=16
supported_ecc=["p192","p224","p256","p384","p521","ed25519","ed448"]


def kdf(x):
    return SHAKE256.new(x).read(32)
    
class common:
    
    def __init__(self,key=None,key_type="p256"):
        if type(key) is str:
            if key.endswith(".key"): key=key[:-4]
            self.key_path=key+"-"+key_type+".key"
            
        self.key_type=key_type
        self.filters=[
        {"id": lzma.FILTER_LZMA2, "preset": 5},
        ]
        self.header=self.password.encode()
        

    def send(self,data,dh=False,connection=None,session_key=None,password=None):
        if dh and password is not None: session_key=PBKDF2(password, 0, 32, count=10000, hmac_hash_module=SHA512)
        if connection is None and not dh: connection=self.connection
        if session_key is None and not dh: session_key=self.session_key
        assert session_key is not None or dh and password is None
        
        data = self.compress(data)
        if session_key is not None:
            data = self.encrypt(session_key,data)

        l_data=len(data)-nonce_len-tag_len 
        if not l_data-4<=2**(8*4): raise Exception("don't send data over 4GiB")
        data = struct.pack('<I',l_data)+struct.pack('<B',0)*2+data
        checksum=SHAKE128.new(data).read(1)

        data = checksum+data
        connection.sendall(data)        
        return True
    
    def recv(self,session_key=None,connection=None,dh=False,password=None):
        if dh and password is not None: session_key=PBKDF2(password, 0, 32, count=10000, hmac_hash_module=SHA512)
        if connection is None and not dh: connection=self.connection
        if session_key is None and not dh: session_key=self.session_key
        assert session_key is not None or dh and password is None
        checksum = connection.recv(1) 
        l_data = connection.recv(4)
        r1 = connection.recv(1)
        r2 = connection.recv(1)
        x=struct.unpack('<I',l_data)[0]  
        data = connection.recv(x)
        nonce = connection.recv(nonce_len)
        tag = connection.recv(tag_len)
        if SHAKE128.new(l_data+r1+r2+data+nonce+tag).read(1) != checksum:
            '''checks for in transport corruption, does not verify data, more for debeugging then anything else'''
            raise Exception("data corrupted") 
        
        if session_key is not None:
            data = self.decrypt(session_key,data,nonce=nonce,tag=tag)
        data = self.decompress(data)

        return data
    
    def compress(self,data):
        return lzma.compress(pickle.dumps(data),format=3,filters=self.filters) # crc is not necessary and format other then RAW is waste of few bytes
    
    def decompress(self,data):
        return pickle.loads(lzma.decompress(data,format=3,filters=self.filters))
    
    def handshake(self,eph_priv,connection,server=False,client=None,password=None):
        if server:
            auth=self.recv(connection=connection,dh=True,password=password)
            self.send(
                (self.key.public_key().export_key(format="PEM"),
                       eph_priv.public_key().export_key(format="PEM")
                 ), connection=connection,dh=True,password=password)

        else:
            self.send(
                (self.key.public_key().export_key(format="PEM"),
                       eph_priv.public_key().export_key(format="PEM")
                 ),
                      connection=connection,dh=True,password=password)
                      
            auth=self.recv(connection=connection,dh=True,password=password)
        
        static_pub=ECC.import_key(auth[0])
        h_obj = BLAKE2b.new(digest_bits=64)
        if server:
            h_obj.update(self.key.public_key().export_key(format="raw"))
            h_obj.update(static_pub.export_key(format="raw"))
        else:
            h_obj.update(static_pub.export_key(format="raw"))
            h_obj.update(self.key.public_key().export_key(format="raw"))
        try:
            
            if not server:
                known_keys_ = sqlite3.connect(self.known_keys)
                known_keys = known_keys_.cursor()
                known_keys.execute("CREATE TABLE IF NOT EXISTS keys (ip TEXT, key TEXT)")
                

                if not known_keys.execute(f"SELECT key FROM keys WHERE ip = ? AND key = ?",(client[0],static_pub.export_key(format="PEM"),)).fetchone(): 
                    res = known_keys.execute(f"SELECT ip FROM keys WHERE key = ?",(static_pub.export_key(format="PEM"),)).fetchall() 
                    if res and not self.headless:
                        print(f"known as: {res}")
                    if not self.trust and not self.headless:
                        input(f"hash is:{h_obj.hexdigest()} continue?")
                    elif not self.trust and self.headless:
                        raise Exception(f"key from {client[0]} not trusted")
                    
                    if not self.headless: print("adding peer key to db")
                    known_keys.execute("INSERT INTO keys VALUES (?,?)",(client[0],static_pub.export_key(format="PEM")))
                    known_keys_.commit()
                    known_keys_.close()
                
            else:
                if not self.headless: print(f"{client}:{h_obj.hexdigest()}")
        except KeyboardInterrupt:
            if not self.headless: print("\nhandshake canceled exiting")
            connection.close()
            sys.exit()
        
            
        eph_pub=ECC.import_key(auth[1])
        h_obj = BLAKE2b.new(digest_bits=256)
        if server:
            h_obj.update(eph_priv.public_key().export_key(format="raw"))
            h_obj.update(eph_pub.public_key().export_key(format="raw"))
        else:
            h_obj.update(eph_pub.public_key().export_key(format="raw"))
            h_obj.update(eph_priv.public_key().export_key(format="raw"))

        self.header=h_obj.hexdigest().encode()

        return key_agreement(static_priv=self.key,
                            static_pub=static_pub,
                            eph_priv=eph_priv,
                            eph_pub=eph_pub,
                            kdf=kdf)
    
    def eph_priv(self):
        if self.key_type in supported_ecc:
            return ECC.generate(curve=self.key_type)
        else: raise Exception(f"key format {self.key_type} not supported")
    
    def loadkey(self):
        if exists(self.key_path):
            with open(self.key_path,"r") as f:
                if self.key_type in supported_ecc: 
                    self.key=ECC.import_key(f.read(),curve_name=self.key_type)
                else: raise Exception(f"key format {self.key_type} not supported")
                
        else:
            if not self.headless: print("Generating new key")
            with open(self.key_path,"w") as f:
                if self.key_type in supported_ecc:
                    self.key=ECC.generate(curve=self.key_type)
                else: raise Exception(f"key format {self.key_type} not supported")
                f.write(self.key.export_key(format="PEM"))

    def encrypt(self,session_key,data):
        assert session_key is not None
        cipher = AES.new(session_key, AES.MODE_GCM, mac_len=tag_len,nonce=get_random_bytes(nonce_len))
        cipher.update(self.header)
        ct, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce 
        return ct+nonce+tag
    
    def decrypt(self,session_key,data, nonce=None,tag=None):
        cipher = AES.new(session_key, AES.MODE_GCM,nonce=nonce, mac_len=tag_len)
        cipher.update(self.header) #i have no idea it is
        return cipher.decrypt_and_verify(data,tag)

class remote_client(common):
    def __init__(self, connection, ip, key,key_type=None,password=None,headless=None):
        self.password = password
        super().__init__(key_type=key_type)
        self.headless=headless
        self.key=key
        self.connection=connection
        self.ip=ip
        self.session_key=common.handshake(self,super().eph_priv(),connection=self.connection,server=True,client=self.ip,password=password)

    def close(self):
        self.connection.close()
    
    def sendall(self, data):
        return common.send(self,data, connection=self.connection, session_key=self.session_key)

    def recvall(self):
        return common.recv(self,session_key=self.session_key, connection=self.connection)




class server(common):
    def __init__(self,address,key,key_type="p256",password=None,headless=True):
        self.password = password
        super().__init__(key,key_type=key_type)
        self.headless=headless
        self.bind(address)
        self.threads=[]
        common.loadkey(self)
        acc_thread=threading.Thread(target=self.accept_con,args=())
        acc_thread.start()
        self.clients=[]
        self.new_clients=[]
    
    def bind(self,address):
        ip,port = address.rsplit(":",1)
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((ip,int(port)))
        tcp_socket.listen()
        self.socket=tcp_socket

    def accept_con(self):
        while True:
            connection,client=self.socket.accept()
            thread = threading.Thread(target=self.handler,args=(connection,client,))
            thread.start()
            self.threads.append(thread)
    
    def wait_for_client(self,clients):
        while True:
            for c in self.clients:
                if c not in clients:
                    return c
            time.sleep(0.1)

    def handler(self,connection,client):
        _client=remote_client(connection,client,self.key,key_type=self.key_type,password=self.password,headless=self.headless)
        self.clients.append(_client)
        return _client

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

            
                
class client(common):
    def __init__(self,address,key,db_name="known_keys.db",key_type="p256",password=None, headless=True,trust=False):
        self.password = password
        super().__init__(key,key_type=key_type)
        self.trust=trust
        self.headless=headless
        common.loadkey(self)
        self.known_keys = db_name
        self.connect(address,password)
        
    def connect(self,address,password):
        ip,port = address.split(":")
        self.connection = socket.create_connection((ip, int(port)))
        self.address = address
        self.session_key = common.handshake(self,common.eph_priv(self),self.connection,client=(str(ip),port),password=password)
    
    def sendall(self,data):
        common.send(self,data)

    def recvall(self):
        return common.recv(self)
    
    def close(self):
        self.connection.close()
    
    def reconnect(self):
        self.close()
        self.connect(self.address)


if __name__ == "__main__":
    port=6021
    s=server(f"127.0.0.1:{port}","server.key",password="test",headless=False)
    c=client(f"127.0.0.1:{port}","client.key",password="test",headless=False) 
    c.sendall("works")
    print(s.clients[0].recvall())