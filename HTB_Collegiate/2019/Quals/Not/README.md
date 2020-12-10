# Not

- Category: Crypto
- Points: 200 (100)

## Challenge

### Files

- `not.png`
- `notnot.png`

## Solution

We are given two files:

`not.png`

![image-20191121115244094](image-20191121115244094.png)

And `notnot.png`:

![image-20191121115319632](image-20191121115319632.png)

Looking at these and their names, it's fairly obvious that we need to do some kind of pixel manipulation to reveal the flag.

We overlay them in GIMP, color all white text in the second one black, overlay them, and squint really hard.

![image-20191121132548649](image-20191121132548649.png)

### Flag

`HTB{1_t1m3_p4d_s0_b4d}`