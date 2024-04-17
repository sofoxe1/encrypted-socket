class bytelist:
    def __init__(self,data):
        self.data = data
        self.cursor=0
    
    def seek(self,position):
        self.cursor = position

    def seek_back(self,position):
        self.cursor = len(self.data) - position
    
    def read(self,lenght):
        if lenght+self.cursor <= len(self.data):
            x = self.data[self.cursor:self.cursor+lenght]
            self.cursor = lenght+self.cursor
            return x
        else:
            raise IndexError("index out of range")
    
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

    def __getitem__(self,item):
        return self.data[item]        

