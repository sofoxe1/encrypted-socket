from os.path import exists
from pympler.asizeof import asizeof as getsize
import math
import time
import sqlite3
import threading
try:
    from net import client,server
except:
    from .net import client,server

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
    
    def list_peers(self):
        peers_db = sqlite3.connect(self.db, isolation_level=None)
        peers_t = peers_db.cursor()
        return peers_t.execute("SELECT * FROM peers").fetchall()
        peers_db.close()

    def add_peer(self,peer_id,address):
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
            q=[remote.peer_id,f"{remote.peer_ip()}:{remote.recvall()}",remote]
            self.active_connections.append(q)
            t=threading.Thread(target=self._handler, args=(remote,))
            t.start()
            self.add_peer(q[0],q[1])
            
    
    def get_connection(self,peer_id):
        for conn in self.active_connections:
            if conn[0] == peer_id:
                return conn[2]
        try:
            peers_db = sqlite3.connect(self.db)
            peers_t = peers_db.cursor()
            r=peers_t.execute("SELECT address FROM peers WHERE peer_id = ?",([peer_id])).fetchone()[0]
            peers_db.close()
            return self.connect(r)
        except:
            self.remove_peer(peer_id)
            return False
    
    def connect(self,address):
        conn = client(address,key=self.key,password=self.password,headless=True,trust=True)
        conn.sendall(self.port)
        self.active_connections.append([conn.peer_id,address,conn])
        self.add_peer(conn.peer_id,address)
        t=threading.Thread(target=self._handler, args=(conn,))
        t.start()
        return conn
    
    def peer_send(self,peer_id,data):
        conn=self.get_connection(peer_id)
        if conn == False:
            raise P2PException(f"no route to {peer_id}")
        conn.sendall(data)
        return True
    def _handler(self,remote):
        while True:
            msg=remote.recvall()
            self.handler(remote.peer_id,msg)



if __name__ == "__main__":
    a=P2P(password=":3",db_path="peers1.db",key="sync1.key",address=":::5482",handler=rcv)
    b=P2P(password=":3",db_path="peers2.db",key="sync2.key",address=":::5485",handler=rcv)
    print(b.list_peers())
    a.connect("127.0.0.1:5485")
    print(b.list_peers())
    b.peer_send("0e4b43fb5c7ce118202208f75ef8b7e3",b"uj")


    