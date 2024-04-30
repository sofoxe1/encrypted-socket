from Cryptodome.Hash import SHAKE256
import time
import datetime
class bytelist:
    def __init__(self,data):
        self.data = data
        self.l_data=len(self.data)
        self.cursor=0
    
    def seek(self,position):
        self.cursor = position

    def seek_back(self,position):
        self.cursor = self.l_data - position
    
    def read(self,lenght,end=True):
        if lenght+self.cursor <= self.l_data:
            x = self.data[self.cursor:self.cursor+lenght]
            self.cursor = lenght+self.cursor
            return x
        elif end:
            x = self.data[self.cursor:self.l_data]
            self.cursor = self.l_data
            return x
        else:
            raise IndexError("index out of range")
    
    def truncate(self,end_bytes=0):
        self.data = self.data[:-end_bytes]
        self.l_data=len(self.data)
    
    def pos(self, position):
        return self.cursor

    def __add__(self,other):
        return bytelist(self.data+bytes(other))

    def __eq__(self,other):
        return self.data == bytes(other)

    def __ne__(self,other):
        return not self.__eq__(other)

    def __bytes__(self):
        return self.data
    
    def __repr__(self):
        return self.__str__()
    
    def __str__(self):
        return str(self.data)

    def __bool__(self):
        return not self.cursor == self.l_data

    def __getitem__(self,item):
        return self.data[item]

def _hash(hash_lenght,*args):
    shake =SHAKE256.new()
    for arg in args:
        shake.update(arg)
    return shake.read(hash_lenght)

class Timer:
    def __init__(self):
        self.t=time.time()
    def elapsed(self):
        return datetime.timedelta(seconds=time.time()-self.t)
    def __repr__(self):
        return str(self.elapsed())


