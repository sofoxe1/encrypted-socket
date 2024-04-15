
from Crypto.Hash import SHAKE128
import pickle
import time
import inspect
import threading
try:
    from .net import client,server
except:
    from net import client,server

class HT:

    
    def __init__(self,hash_lenght=4): 
        self.hash_lenght=hash_lenght
        self.objects={}
        self._ht=lambda: self._hash_obj(pickle.dumps(self.objects))
        self.diff=[] 
    
    def _hash_obj(self,obj:bytes) -> bytes:
        return SHAKE128.new(data=obj).read(self.hash_lenght)

    def _action(self,obj:bytes =None,item=None) -> bool:
        assert self.check(locals())
        _r=False
        func=inspect.stack()[1][3]
        
        if obj is not None and item is None:
            obj_hash=self._hash_obj(obj)
        elif obj is None and item is not None:
            obj_hash=item
        else:
            raise Exception("pass either object or hash of it, not both")
        action=f"{func}:{obj_hash}"
        org_hash=self._ht()
        match func:
            case "_add":
                if obj_hash not in self.objects:
                    self.objects[obj_hash]=obj
                    _r = True
                elif self.objects[obj_hash] != obj:
                    raise Exception("hash collision, increase hash_lenght")
                else:
                    _r = False #already exists
                        
            case x if x in ["remove","remove_item"]:
                if obj_hash not in self.objects:
                    _r = False
                else:
                    self.objects.pop(obj_hash)


            
        
        new_hash=self._ht()
        self.diff.append([org_hash,action,new_hash])
        return _r


    def check(self,args):
        for arg in args.keys():
            match arg:
                case "self":
                    continue
                case x if args[x] is None:
                    continue
                case x if x.startswith("item") or x.startswith("hash"):
                    if type(args[arg]) != bytes or len(args[arg]) != self.hash_lenght:
                        raise ValueError(f"{arg}:{args[arg]} should be bytes with len of {self.hash_lenght}")
                case x  if x.startswith("obj"):
                    if type(args[arg]) == bytes and len(args[arg]) == self.hash_lenght:
                        print("WARN: you may be passing hash as object")   
                case _:
                    raise Exception(f"{arg}:{args[arg]}")
        return True

    
    def keys(self) -> list:
        return list(iter(self.objects.keys()))

    def _add(self,obj):
        return self._action(obj=obj)
        
    def remove(self,obj):
        return self._action(obj=obj)

    def remove_item(self,item):
        return self._action(item=item)
    
    def exists(self,obj):
        return self._hash_obj(obj,False) in self.objects

    def __str__(self):
        return str(self.objects)

    def __bytes__(self):
        return __repr__()
    
    def hash(self,obj):
        x=self._hash_obj(obj)
        if x in self.objects:
            return x
        else:
            return None
    
    def __getitem__(self,item):
        return self.objects[item]




class DHT:
    def __init__(self,password,port):
        self.password = password
        self.storage = HT()
        self.remote_ht=[]
        self.local = []
        self.listener=server(f":::{port}","buff_server.key",password=password,headless=True)
        a=threading.Thread(target=self.accept,args=())
        a.start()

    def accept(self):
        self.active_connections=[]
        while True:
            remote=self.listener.accept()
            self.active_connections.append(remote)
            t=threading.Thread(target=self.handler, args=(remote,))
            t.start()
    
    def handler(self,conn):
        while True:
            msg=conn.recvall()
            if type(msg) is list:
                match msg[0]:
                    case 1:
                        self.remote_ht[conn.peername]=msg[1]
                    case 2:
                        print("q")
                        self.add(msg[2])
                        print(self.storage.hash(msg[2]))

            else:
                raise Exception("dfkusghfj")
    
    def connect(self,address):
        remote=client(address,"ht.key",password=self.password,headless=True,trust=True)
        self.active_connections.append(remote)
        t=threading.Thread(target=self.handler, args=(remote,))
        t.start()
    
    def broadcast(self):
        for conn in self.active_connections:
            conn.sendall([1,self.storage.keys()]) 
    
    def push(self):
        for conn in self.active_connections:
            for d in self.local:
                print(d)
                if bool(int(time.time()) - d[1]<= 0 or d[1] == 0)   and d[2]:
                    conn.sendall([2,d[0],self.storage[d[0]]])
    
    def add(self,data,push=False,ttl=0): 
        expires=0
        if ttl != 0:
            expires=int(time.time())+ttl
        if self.storage._add(data):
            self.local.append([self.storage.hash(data),expires,push])

    def keys(self) -> list:
        return self.storage.keys()
        
    def __getitem__(self,item):
        return self.storage[item]

    


if __name__ == "__main__":        
    a=DHT(password="pass123",port=7820)
    a.add("test1".encode(),push=True)
    b=DHT(password="pass123",port=7821)
    b.add("b2".encode())
    print(a.storage)
    print(b.storage)
    a.connect("127.0.0.1:7821")
    a.push()
    time.sleep(1)
    print(a.storage)
    print(b.storage)
    print(b[b.keys()[1]])

 