import ctypes

_shlib = ctypes.CDLL('./skeinhash/skeinhash.so')

def skeinhash(msg):
    msgb = ctypes.create_string_buffer(msg)
    hashb = ctypes.create_string_buffer(32)
    _shlib.skeinhash(hashb, msgb, len(msg))
    return hashb.raw

def skeinhashmid(msg):
    msgb = ctypes.create_string_buffer(msg[:64])
    hashb = ctypes.create_string_buffer(64)
    _shlib.skeinhashmid(hashb, msgb, 64)
    return hashb.raw

if __name__ == '__main__':
    mesg = "dissociative1234dissociative4567dissociative1234dissociative4567dissociative1234"
    h = skeinhashmid(mesg)
    print h.encode('hex')
    print 'ad0d423b18b47f57724e519c42c9d5623308feac3df37aca964f2aa869f170bdf23e97f644e81511df49c59c5962887d17e277e7e8513345137638334c8e59a4' == h.encode('hex')

    h = skeinhash(mesg)
    print h.encode('hex')
    print '764da2e768811e91c6c0c649b052b7109a9bc786bce136a59c8d5a0547cddc54' == h.encode('hex')