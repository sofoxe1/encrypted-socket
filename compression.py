import lzma
import os
from difflib import SequenceMatcher
import pickle
from sys import getsizeof
import collections
import struct
from Crypto.Hash import SHAKE128
try:
    from shared import bytelist
except:
    from .shared import bytelist

#well it does stuff, resulting in better compression ratio then simply calling lzma.compress
dict_hash_len = 2 
default_words = " ".join(open(f"{os.path.dirname(__file__)}/default_words.txt","r").read().split("\n")).encode()
dictionaries={SHAKE128.new(data=pickle.dumps(default_words)).read(dict_hash_len):default_words}

def create_dictionary(words,dict_size, blacklist=[],binary=False):
    if binary:
        raise ValueError("binary mod is not implemented")
    elif not binary == bool(not True == binary):
        counter = collections.Counter(words)
        counter = [x for x in a if x not in blacklist]
        frequent = []
        c=counter.most_common()
        for i in range(dict_size):
            frequent.append(c[i][0])

        _hash=SHAKE128.new(pickle.dumps(frequent)).read(2)
        try:
            dictionaries.update({_hash:frequent})
        except:
            pass
        return _hash


def get_stuff(_a,ab): # magick function that does stuff, there is probably a better way to do this
    match = SequenceMatcher(None, _a, ab).find_longest_match(
        0, len(_a), 0, len(ab))
    a=ab[match.a + match.size:]
    b=ab[:match.a]
    _a=struct.pack("<h",len(a))
    _b=struct.pack("<h",len(b))
    stuff_data=_a+_b+a+b+struct.pack("<h",match.size)+struct.pack("<h",match.a)
    
    return stuff_data
def decode_stuff(q,stuff_data): # magick function that undoes stuff
    stuff_data=bytelist(stuff_data)
    _a=struct.unpack("<h",stuff_data.read(2))[0]
    _b=struct.unpack("<h",stuff_data.read(2))[0]
    a=stuff_data.read(_a)
    b=stuff_data.read(_b)
    match_size=struct.unpack("<h",stuff_data.read(2))[0]
    match_a=struct.unpack("<h",stuff_data.read(2))[0]
    return bytes(b+q[match_a:match_a + match_size]+a)

def compress(data,auto=False,a=None,preset=4):
    # assert auto != bool(a is None 
    if a is not None:
        if type(a) == int:
            a=list(dictionaries.values())[0]
        _a=lzma.compress(a,format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])
        ab=lzma.compress(a+"<!>".encode()+pickle.dumps(data),format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])
        x = get_stuff(_a,ab)
        if auto:
            z=lzma.compress(pickle.dumps(data),format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])
            if getsizeof(x)<getsizeof(z):
                return SHAKE128.new(data=pickle.dumps(a)).read(2),True,x
            else:
                return False,z
        else:
            return x

    elif a is None:
        return lzma.compress(pickle.dumps(data),format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])

def decompress(data,a=None,preset=4):
    if a is not None:
        if type(a) == int:
            listt(dictionaries.values())[0]
        return pickle.loads(
            lzma.decompress(
                decode_stuff(lzma.compress(a,format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}]),data
                            ),format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}]
                            ).split("<!>".encode())[1]
                            ) 
    else:
        return pickle.loads(lzma.decompress(data,format=3,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}]))



if __name__ == "__main__":
    from wonderwords import RandomWord,RandomSentence
    a=RandomSentence().sentence()
    b=" ".join(RandomWord().random_words(3))
    assert decompress(compress(b)) == b
    assert decompress(compress(b,a=a),a)==b
    # print(len(compress(b)))
    # print(len(compress(b,a=a,auto=False)))

