a = 'abcdef'
n = '0123456789'

def add(a,b,c,d):
    return ord(a)+ord(b)+ord(c)+ord(d)

def xor(a,b,c,d):
    return ord(a)^ord(b)^ord(c)^ord(d)


d2 = 'f'
for d1 in a:
    for d3 in n:
        for d4 in a:
            if add(d1,d2,d3,d4) == 0x15e and xor(d1,d2,d3,d4) == 0x52:
                print d1, d2, d3, d4
