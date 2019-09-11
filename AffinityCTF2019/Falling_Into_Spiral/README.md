<!-- borrowed from https://github.com/m3ssap0/CTF-Writeups/blob/master/template.md -->
# Affinity CTF 2019 – Falling Into Spiral

* **Category:** Stego
* **Points:** 100

## Challenge

### Files

[sprial.png](spiral.png)

## Solution

Viewing the file we see something malformed, if we think back to the title we might be able to tell that the file is just swirled. So either using online methods or [gimp](https://www.gimp.org/). I used gimp and went to filter -> distorts -> Whirl and Pinch; then set the value to 1000 we see what looks like a flag upside down. Rotating the image we get our 
!(flag.png)[flag.png].


### Flag
```
AFFCTF{h3arly_He4rly_th1s_Was_sw1rly_!!!}
```
