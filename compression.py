import lzma
from difflib import SequenceMatcher
import pickle
from sys import getsizeof
import collections
from Crypto.Hash import SHAKE128

#well it does stuff, resulting in better compression ratio then simply calling lzma.compress

default_words = " ".join(open("default_words.txt","r").read().split("\n")).encode()
dictionaries={SHAKE128.new(data=pickle.dumps(default_words)).read(4):default_words}

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

        _hash=SHAKE128.new(pickle.dumps(frequent)).read(4)
        try:
            dictionaries.update({_hash:frequent})
        except:
            pass
        return _hash



def get_stuff(_a,ab): # magick function that does stuff
    _a=bytearray(_a)
    ab=bytearray(ab)

    match = SequenceMatcher(None, _a, ab).find_longest_match(
        0, len(_a), 0, len(ab))
    m=_a[match.a:match.a + match.size]
    _ab=ab[:match.a]+_a[match.a:match.a + match.size]+ab[match.a + match.size:]
    stuff_data=ab[match.a + match.size:]+"<d>".encode()+ab[:match.a]+f"<d>{match.a}".encode()+f"<d>{match.size}".encode()
    return stuff_data
def decode_stuff(a,stuff_data): # magick function that undoes stuff

    stuff_data=stuff_data.split("<d>".encode())
    assert len(stuff_data) == 4
    match_size=int(stuff_data[3].decode())
    match_a=int(stuff_data[2].decode())
    return bytes(stuff_data[1]+a[match_a:match_a + match_size]+stuff_data[0])

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
                return SHAKE128.new(data=pickle.dumps(a)).read(4),True,x
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

