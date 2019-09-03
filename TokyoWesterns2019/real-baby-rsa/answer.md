# CTF Name - real_baby_rsa

* **Category:** Crypto
* **Points:** 40

## Challenge

### Description
None given

### Files
* problem.py
* output.txt

## Solution

Based on the factors to encrypt the data the result of a given character will never change.
Answer.py will encrypt each character, output the result, and also output the index into the char string so you can match it up by hand
 
Go through and match output of answer.py to the output file

```
N = 36239973541558932215768154398027510542999295460598793991863043974317503405132258743580804101986195705838099875086956063357178601077684772324064096356684008573295186622116931603804539480260180369510754948354952843990891989516977978839158915835381010468654190434058825525303974958222956513586121683284362090515808508044283236502801777575604829177236616682941566165356433922623572630453807517714014758581695760621278985339321003215237271785789328502527807304614754314937458797885837846005142762002103727753034387997014140695908371141458803486809615038309524628617159265412467046813293232560959236865127539835290549091
e = 65537

f = open("../Downloads/real-baby-rsa/output")
data = f.readlines()
print(data[0])

flag = """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890?,./<>?!@#$%^&*()-_=+"""
for char in flag:
    x = pow(ord(char), e, N)
    print(x)
    # For some reason doesn't work as I expected so I did it by hand
    for i in data:
        if x == i:
            print(char)

j = 1
for i in flag:
    print(str(j) + " : " + i)
    j += 1
```

### Flag

```
TWCTF{padding_is_important}
```
