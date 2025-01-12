from os.path import exists,getsize
from pympler.asizeof import asizeof as getsizeof
import math
import time
import sys
import sqlite3
import threading
from tqdm import tqdm
try:
    from net import client,server
    from shared import _hash
except:
    from .net import client,server
    from .shared import _hash

class P2PException(Exception):
    pass

class P2P:
    def __init__(self,password,address=":::5483",db_path="peers.db",key="sync.key",handler=None):
        self.port = int(address.rsplit(":",1)[1])
        self.password = password
        self.handler=handler
        peers_db = sqlite3.connect(db_path, isolation_level=None)
        peers_t = peers_db.cursor()
        peers_t.execute("CREATE TABLE IF NOT EXISTS peers (peer_id TEXT, address TEXT)")
        self.db=db_path
        peers_db.close()
        self.server = server(address,key=key,password=password,headless=True)
        self.key=key
        self.id=self.server.id()
        t=threading.Thread(target=self.accept,args=())
        t.start()
        t=threading.Thread(target=self.request_peers,args=())
        t.start()
    
    def list_peers(self,check=False,_all=False):
        peers_db = sqlite3.connect(self.db, isolation_level=None)
        peers_t = peers_db.cursor()
        if check:
            x=peers_t.execute("SELECT address FROM peers").fetchall()
        if _all:
            x=peers_t.execute("SELECT * FROM peers").fetchall()
        else:
            x=peers_t.execute("SELECT peer_id FROM peers").fetchall()

        peers_db.close()
        return x

    def _add_peer(self,peer_id,address):
        peers_db = sqlite3.connect(self.db)
        peers_t = peers_db.cursor()
        peers_t.execute("DELETE FROM peers WHERE peer_id = ?",([peer_id]))
        peers_t.execute("INSERT INTO peers VALUES (?,?)",(peer_id,address))
        peers_db.commit()
        peers_db.close()

    def remove_peer(self,peer_id):
        for x in self.active_connections:
            if x[0] ==peer_id:
                self.active_connections.pop(x)
                break
        peers_db = sqlite3.connect(self.db)
        peers_t = peers_db.cursor()
        peers_t.execute("DELETE FROM peers WHERE peer_id = ?",([peer_id]))
        peers_db.commit()
        peers_db.close()

    def accept(self):
        self.active_connections=[]
        while True:
            remote=self.server.accept()
            q=[remote.peer_id,f"{remote.peer_ip()}:{remote.recvall()}",remote,threading.Lock()]
            self.active_connections.append(q)
            t=threading.Thread(target=self._handler, args=(remote,))
            t.start()
            self._add_peer(q[0],q[1])
            
    
    def get_connection(self,peer_id):
        for conn in self.active_connections:
            if conn[0] == peer_id:
                return conn[3],conn[2]
        try:
            peers_db = sqlite3.connect(self.db)
            peers_t = peers_db.cursor()
            r=peers_t.execute("SELECT address FROM peers WHERE peer_id = ?",([peer_id])).fetchone()[0]
            peers_db.close()
            return self.connect(r)
        except:
            self.remove_peer(peer_id)
            return False,False
    
    def add_peer(self,address):
        if not address in self.list_peers(check=True):
            self.connect(address)

    def connect(self,address):
        conn = client(address,key=self.key,password=self.password,headless=True,trust=True)
        conn.sendall(self.port)
        lock=threading.Lock()
        self.active_connections.append([conn.peer_id,address,conn,lock])
        self._add_peer(conn.peer_id,address)
        t=threading.Thread(target=self._handler, args=(conn,))
        t.start()
        return lock,conn
    
    def peer_send(self,peer_id,data,compress=True):
        lock,conn=self.get_connection(peer_id)
        if conn == False:
            raise P2PException(f"no route to {peer_id}")
        # lock.acquire()
        conn.sendall(data,compress=compress,lock=lock)
        # lock.release()
        return True

    def broadcast(self,data):
        for x in self.list_peers():
            self.peer_send(x[0],data)

    def exchange_peers(self,msg):
        local_peers=self.list_peers(check=True)
        for x in msg:
            if x[0] not in local_peers and x[0] !=self.id:
                self._add_peer(x[0],x[1])

    def request_peers(self):
        time.sleep(0.5)
        while True:
            self.broadcast([-1])
            time.sleep(60)

    def _handler(self,remote):
        while True:
            msg=remote.recvall()
            if type(msg) == list and len(msg)>=1:
                match msg[0]:
                    case -1:
                        self.peer_send(remote.peer_id,[-2,self.list_peers(_all=True)])
                    case -2:
                        self.exchange_peers(msg[1])
                    case _:
                       self.handler(remote.peer_id,msg) 
            else:
                self.handler(remote.peer_id,msg)

class Sync:
    def __init__(self,password,chunk_size=(2**20),address=":::5483",db_path="peers.db",key="sync.key"):
        self.chunk_size = chunk_size
        self.files=[]
        self.p2p=P2P(password=password,address=address,handler=self.handler,db_path=db_path,key=key)
        self.peer_files={}
        self.buffer={}
        self.open_files={}
        self.s=0
    
    def read_chunk(self,file_hash,pos):
        try:
            f=self.open_files[file_hash]
        except:
            f=open(self.get_file_path(file_hash),"rb")
            self.open_files[file_hash]=f
        
        f.seek(pos)
        return f.read(self.chunk_size)

    def get_file_path(self,file_hash):
        for f in self.files:
            if f[0]==file_hash:
                return f[1]
        raise Exception(f"File with hash {file_hash} doesn't exist")

    def handler(self,peer_id,data):
        assert type(data) is list
        match data[0]:
            case 0:
                for x in data[1]:
                    self.peer_files[x[0]]=[peer_id]+x[1:]
            case 1:
                self.p2p.peer_send(peer_id,[0,self.files])
            case 2:
                l=lambda: self.p2p.peer_send(peer_id,[3,self.read_chunk(data[1],data[2]),data[3]])
                t=threading.Thread(target=l,args=())
                t.start()
                
            case 3:
                self.buffer[data[2]]=data[1]
            case _:
                raise Exception(f"unknown command {data[0]}")

    def add_file(self,file_path):
        if not exists(file_path):
            raise Exception("File does not exist: {}".format(file_path))
        f=open(file_path,"rb")
        chunk_count=math.ceil(getsize(file_path)/self.chunk_size)
        self.files.append([_hash(128,f.read(1024)),file_path,getsize(file_path),[x*self.chunk_size for x in range(chunk_count)]])
        f.close()
    
    def broadcast(self):
        self.p2p.broadcast([0,self.files])
    
    def request_update(self):
        self.p2p.broadcast([1])   
    
    def _get_remote_hash(self,file_name):
        if self.isfilehash(file_name):
            return file_name
        q=[]
        for v in self.peer_files:
            if self.peer_files[v][1]==file_name:
                q.append(v)
        if len(q)==0:
            raise P2PException(f"remote file {_file} not found")
        elif len(q)>1:
            raise Exception(f"multiple files {_file} specify peer or use file hash")
        else:
            return q[0]


    def isfilehash(self,data):
        return type(data) is bytes and len(data) == 128

    def download(self,_file,path,overwrite=False,blocking=False):
        file_hash=None
        for i in range(10):
            try:
                file_hash=self._get_remote_hash(_file)
                peer_id=self._get_peer_id(file_hash)
                break
            except P2PException:
                time.sleep(0.2)
        if file_hash==None:
            raise Exception("unable to locate file")
        if exists(path) and not overwrite:
            raise Exception(f"file {path} exisists pass overwrite=True to ignore")
        f=open(path,"wb")
        t=threading.Thread(target=self._downloader,args=(f,file_hash,peer_id))
        t.start()
        if blocking:
            t.join()

    def _chunk_downloader(self,f_out,file_hash,peer_id,chunks,lock):
        for c in tqdm(chunks):
            s=str(file_hash)+str(c)
            self.p2p.peer_send(peer_id,[2,file_hash,c,s])
            for ii in range(1000):
                try:
                    a=self.buffer[s]
                    lock.acquire()
                    f_out.seek(c)
                    f_out.write(a)
                    lock.release()
                    del self.buffer[s]
                    break
                except KeyError:
                    time.sleep(0.01)
                    
            if ii == 999:
                raise Exception(f"download of {file_hash} from {peer_id} timed out")
                break

    def _downloader(self,f_out,file_hash,peer_id,thread_count=6):
        q=lambda x,s:[[*x[i:i+s]] for i in range(0,len(x),s)]
        chunks=self.peer_files[file_hash][3]
        chunks=q(chunks,math.ceil(len(chunks)/thread_count))
        f_out_lock=threading.Lock()
        threads=[]
        for i in range(thread_count):
            t=threading.Thread(target=self._chunk_downloader,args=(f_out,file_hash,peer_id,chunks[i],f_out_lock))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        f_out.close()
        return True
                

    def _get_peer_id(self,file_hash):
        return self.peer_files[file_hash][0]
        



def rcv():
    pass

if __name__ == "__main__":
    q=Sync(password="pass123",address=":::5483")
    q.add_file("net.py")
    q.add_file("LICENSE")
    q.add_file("b.bin")
    q2=Sync(password="pass123",address=":::5484",db_path="peers2.db",key="sync2.key")
    q2.p2p.add_peer(":::5483")
    q3=Sync(password="pass123",address=":::5485",db_path="peers3.db",key="sync3.key")
    q3.p2p.add_peer(":::5484")
    time.sleep(0.5)
    q3.request_update()
    time.sleep(1)
    print(q2.p2p.list_peers(_all=True))

    q3.download("b.bin","a.bin",blocking=True,overwrite=True)


    