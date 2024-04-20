import socket
import sys
import struct
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512,SHAKE256
from Cryptodome.Protocol.DH import key_agreement
from Cryptodome.Random import get_random_bytes
from os.path import exists
import threading
import time
import sys
import sqlite3
try:
    import compression
    from shared import _hash,bytelist
except:
    from . import compression
    from .shared import _hash,bytelist
#checksum(1B),l_data(2B),options(1B),reserved(1B),(data,nonce,tag)

'''
creates encrypted connection between two devices
features:
"safe" aes-gcm encryption
compressions
Elliptic-curve Diffie–Hellman
preshared password used for key exchange (optional) 
ability to chose eliptic curve algorithm 
ability to set nonce and tag len for aes-gcm 
no concern for coding conventions 
random variable/function names

options bitmask:
0: no compression
1: dictionary compresed (data,nonce,tag) -> (data,dictionary hash,nonce,tag)
2: fragmented (unset for last packet)
3-7: ignored for now
'''


supported_ecc=["p192","p224","p256","p384","p521","ed25519","ed448"]
mtu=1500

def kdf(x):
    return SHAKE256.new(x).read(32)
    
class common:
    
    def __init__(self,key=None,key_type="p256"):
        self.write_key = True
        if type(self).__name__ == "remote_client":
            pass
        elif key is None or key == "": #idk why it can be both
            self.key_path = None
            self.write_key = False
        
        else:
            if key.endswith(".key"): key=key[:-4]
            self.key_path=key+"-"+key_type+".key"
        

        self.key_type=key_type
        if self.password is not None: self.header=self.password.encode()
        
    def send(self,data,dh=False,connection=None,password=None,compress=True,auto_compress=False,lock=None):
        if dh and password is not None: session_key=PBKDF2(password, 0, 32, count=10000, hmac_hash_module=SHA512)
        if not dh: session_key=self.session_key
        if connection is None and not dh: connection=self.connection
        dict_hash=None
        options=[False for i in range(8)]
        if compress and auto_compress:
            t = compression.compress(data,auto=True,a=0)
            if len(t)==3:
                dict_hash,options[1],data=t
            else:
                options[1],data=t
        elif compress and not auto_compress:
            data=compression.compress(data)
        else:
            options[0]=True

        if "session_key" in locals():
            data = self.encrypt(session_key,data)

        l_data=len(data)
        fragment=l_data-5>mtu
        if lock is not None: lock.acquire()
        if not fragment:
            self._send(data,connection=connection,options=options,l_data=l_data,dict_hash=dict_hash)
        else:
            data=bytelist(data)
            while data:
                d=data.read(mtu-5)
                if len(d) == mtu-5:
                    options[2]=True
                else: options[2]=False
                l_data=len(d)
                self._send(d,connection=connection,options=options,l_data=l_data,dict_hash=dict_hash)
        if lock is not None: lock.release()
    def _send(self,data,connection=None,options=None,l_data=None,dict_hash=None):
        if options[1] == True:
            options="".join([str(int(options[i])) for i in range(8)]) 
            data = struct.pack('<H',l_data)+struct.pack('<B',int(options,2))+struct.pack('<B',0)+dict_hash+data
        else:
            options="".join([str(int(options[i])) for i in range(8)])
            data = struct.pack('<H',l_data)+struct.pack('<B',int(options,2))+struct.pack('<B',0)+data
        
        checksum=_hash(1,data)

        data = checksum+data
        connection.sendall(data)        
        return True

    def recv(self,connection=None,dh=False,password=None):
        if dh and password is not None: session_key=PBKDF2(password, 0, 32, count=10000, hmac_hash_module=SHA512)
        if connection is None and not dh: connection=self.connection
        if not dh: session_key=self.session_key
        
        
        checksum = connection.recv(1) 
        l_data = connection.recv(2)
        _options = connection.recv(1)
        r2 = connection.recv(1)
        x=struct.unpack('<H',l_data)[0]
        options = [bool(int(x)) for x in bin(struct.unpack("<B",_options)[0])[2:]]
        while len(options)<8:
            options=[False]+options
        
        if options[1]: dict_hash=connection.recv(compression.dict_hash_len)
        data = bytelist(connection.recv(x))
        fragment=False
        while options[2]:
            fragment=True
            checksum = connection.recv(1) 
            l_data = connection.recv(2)
            _options = connection.recv(1)
            r2 = connection.recv(1)
            x=struct.unpack('<H',l_data)[0]
            options = [bool(int(x)) for x in bin(struct.unpack("<B",_options)[0])[2:]]
            
            while len(options)<8:
                options=[False]+options
            if options[1]: dict_hash=connection.recv(compression.dict_hash_len)
            d=connection.recv(x)
            if options[1]:
                a=l_data+_options+r2+dict_hash+bytes(d)
            else:
                a=l_data+_options+r2+bytes(d)
            if _hash(1,a) != checksum:
                '''more for debeugging then anything else'''
                raise Exception("data corrupted or incompatible settings")
            data+=bytelist(d)

        if not fragment: 
            if options[1]:
                a=l_data+_options+r2+dict_hash+bytes(data)
            else:
                a=l_data+_options+r2+bytes(data)
            if _hash(1,a) != checksum:
                '''more for debeugging then anything else'''
                raise Exception("data corrupted or incompatible settings") 
            

        if "session_key" in locals():
            data = self.decrypt(session_key,data)
        
        if not options[0]:
            if options[1]:
                data = compression.decompress(data,a=compression.dictionaries[dict_hash])
            else:
                data=compression.decompress(data)

        return data
    
    def handshake(self,eph_priv,connection,server=False,client=None,password=None):
        if server:
            auth=self.recv(connection=connection,dh=True,password=password)
            self.send(
                (self.key.public_key().export_key(format="PEM"),
                       eph_priv.public_key().export_key(format="PEM")
                 ,self.write_key), connection=connection,dh=True,password=password)

        else:
            self.send(
                (self.key.public_key().export_key(format="PEM"),
                       eph_priv.public_key().export_key(format="PEM")
                 ,self.write_key),
                      connection=connection,dh=True,password=password)
                      
            auth=self.recv(connection=connection,dh=True,password=password)
        static_pub=ECC.import_key(auth[0])
        self.peer_id=_hash(32,static_pub.public_key().export_key(format="raw")).hex()

        if server:
            h_obj = _hash(16,self.key.public_key().export_key(format="raw"),
            static_pub.export_key(format="raw"))
        else:
            h_obj = _hash(16,static_pub.export_key(format="raw"),
            self.key.public_key().export_key(format="raw"))
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
                        input(f"hash is:{h_obj.hex()} continue?")
                    elif not self.trust and self.headless:
                        raise Exception(f"key from {client[0]} not trusted")
                    
                    if self.write_key and auth[2]:
                        if not self.headless: print("adding peer key to db")
                        known_keys.execute("INSERT INTO keys VALUES (?,?)",(client[0],static_pub.export_key(format="PEM")))
                        known_keys_.commit()
                    known_keys_.close()
                
            else:
                if not self.headless: print(f"{client}:{h_obj.hex()}")
        except KeyboardInterrupt:
            if not self.headless: print("\nhandshake canceled exiting")
            connection.close()
            sys.exit()
        
            
        eph_pub=ECC.import_key(auth[1])
        if server:
            h_obj = _hash(256,eph_priv.public_key().export_key(format="raw"),
            eph_pub.public_key().export_key(format="raw"))
        else:
            h_obj = _hash(256,eph_pub.public_key().export_key(format="raw"),
            eph_priv.public_key().export_key(format="raw"))

        self.header=h_obj.hex().encode()

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
        if self.key_path is None and self.password is None:
            raise Exception("you have to specify key path/password or both")
        elif self.key_path is None and self.password is not None:
            self.key=ECC.generate(curve=self.key_type)
        elif exists(self.key_path):
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
        cipher = AES.new(session_key, AES.MODE_GCM, mac_len=self.tag_len,nonce=get_random_bytes(self.nonce_len))
        cipher.update(self.header)
        ct, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        return ct+nonce+tag
    
    def decrypt(self,session_key,data):
        data.seek_back(self.nonce_len+self.tag_len)
        nonce=data.read(self.nonce_len)
        tag=data.read(self.tag_len)
        data.truncate(self.nonce_len+self.tag_len)
        data=bytes(data)
        cipher = AES.new(session_key, AES.MODE_GCM,nonce=nonce, mac_len=self.tag_len)
        cipher.update(self.header) #i have no idea that is
        return cipher.decrypt_and_verify(data,tag)
    
    def peername(self):
        return f"{self.connection.getpeername()[0]}:{self.connection.getpeername()[1]}"

    def peer_ip(self):
        return self.connection.getpeername()[0]

    def id(self):
        return _hash(32,self.key.public_key().export_key(format="raw")).hex()

    def peerid(self):
        return self.peer_id


    
    

class remote_client(common):
    def __init__(self, connection, ip, key,key_type=None,password=None,headless=None,nonce_len=None,tag_len=None):
        self.password = password
        self.nonce_len=nonce_len
        self.tag_len=tag_len
        self.key=key
        super().__init__(key_type=key_type)
        self.headless=headless
        self.connection=connection
        self.ip=ip
        self.session_key=common.handshake(self,super().eph_priv(),connection=self.connection,server=True,client=self.ip,password=password)

    def close(self):
        self.connection.close()
    
    def sendall(self, data,compress=True,auto_compress=False,lock=None):
        return common.send(self,data,compress=compress,auto_compress=auto_compress,lock=lock)

    def recvall(self):
        return common.recv(self)


class server(common):
    def __init__(self,address,key,key_type="p256",password=None,headless=True,nonce_len=12,tag_len=16):
        self.password = password
        self.nonce_len=nonce_len
        self.tag_len=tag_len
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
        if ":"in ip:
            tcp_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
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
    
    def accept(self):
        while True:
            for c in self.new_clients:
                if c not in self.clients:
                    self.clients.append(c)
                    return c
            time.sleep(0.1)

    def handler(self,connection,client):
        _client=remote_client(connection,client,self.key,key_type=self.key_type,password=self.password,headless=self.headless,nonce_len=self.nonce_len,tag_len=self.tag_len)
        self.new_clients.append(_client)
        return _client

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

            
                
class client(common):
    def __init__(self,address,key,db_name="known_keys.db",key_type="p256",password=None, headless=True,trust=False,nonce_len=12,tag_len=16):
        self.password = password
        self.nonce_len=nonce_len
        self.tag_len=tag_len
        super().__init__(key,key_type=key_type)
        self.trust=trust
        self.headless=headless
        common.loadkey(self)
        self.known_keys = db_name
        self.connect(address)
        
    def connect(self,address):
        ip,port = address.rsplit(":",1)
        self.connection = socket.create_connection((ip, int(port)))
        self.address = address
        self.session_key = common.handshake(self,common.eph_priv(self),self.connection,client=(str(ip),port),password=self.password)
    
    def sendall(self,data,compress=True,auto_compress=False,lock=None):
        common.send(self,data,compress=compress,auto_compress=auto_compress,lock=lock)

    def recvall(self):
        return common.recv(self)
    
    def close(self):
        self.connection.close()
    
    def reconnect(self):
        self.close()
        self.connect(self.address)
    
    


if __name__ == "__main__":
    port=6021
    s=server(f":::{port}",key="",password="123",headless=True,nonce_len=8,tag_len=10)
    c=client(f"127.0.0.1:{port}",key="",password="123",headless=True,nonce_len=8,tag_len=10,trust=True) 
    time.sleep(1)
    c.sendall("""I then thought that my father would be unjust if he ascribed my neglect
to vice or faultiness on my part, but I am now convinced that he was
justified in conceiving that I should not be altogether free from
blame. A human being in perfection ought always to preserve a calm and
peaceful mind and never to allow passion or a transitory desire to
disturb his tranquillity. I do not think that the pursuit of knowledge
is an exception to this rule. If the study to which you apply yourself
has a tendency to weaken your affections and to destroy your taste for
those simple pleasures in which no alloy can possibly mix, then that
study is certainly unlawful, that is to say, not befitting the human
mind. If this rule were always observed; if no man allowed any pursuit
whatsoever to interfere with the tranquillity of his domestic
affections, Greece had not been enslaved, Cæsar would have spared his
country, America would have been discovered more gradually, and the
empires of Mexico and Peru had not been destroyed.""")
    
    print(s.accept().recvall())
